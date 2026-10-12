import { Readable } from "node:stream";
import type { FileHandle } from "node:fs/promises";

import { artifactDecompressionBudgetBytes } from "../domain/artifactDecompressionBudget.js";
import { OwnedFileHandle } from "../filesystem/OwnedFileHandle.js";
import {
  NonRegularFileReadError,
  RegularFileAdmissionFailure,
  openRegularFile,
} from "../filesystem/RegularFile.js";
import {
  ArtifactReaderFailure,
  sameArtifactEntry,
  type ArtifactEntry,
  type ArtifactReader,
} from "./ArtifactReader.js";
import { abortIfNeeded } from "./ArtifactHash.js";
import {
  findPyInstallerCookie,
  readCArchiveToc,
  type CArchiveEntry,
  type PyInstallerCookie,
} from "./pyinstaller/CArchiveLayout.js";
import {
  archiveUsesEncryption,
  cookieFacts,
  projectPyzContainer,
  projectPyzMember,
  projectStoredMember,
  sealMember,
  type MaterializedMember,
} from "./pyinstaller/CArchiveMembers.js";
import {
  inflateBounded,
  parsePyzArchive,
  type PyzArchive,
  type PyzEntry,
} from "./pyinstaller/PyzArchive.js";
import type { PyInstallerFailure } from "./pyinstaller/PyInstallerFailure.js";

interface PyzImage {
  readonly archive: PyzArchive;
  readonly bytes: Buffer;
}

interface LoadedArchive {
  readonly members: readonly MaterializedMember[];
}

/**
 * Read-only inventory of a PyInstaller CArchive appended to a native executable.
 * Encrypted PYZ entries are reported and not decoded. Code members are not decompiled.
 */
export class PyInstallerArtifactReader implements ArtifactReader {
  readonly format = "pyinstaller" as const;
  #owner: OwnedFileHandle | undefined;
  #loaded: Promise<LoadedArchive> | undefined;
  #budget = 0;
  #charged = 0;
  #facts: readonly string[] = [];
  readonly #members = new Map<string, MaterializedMember>();

  constructor(private readonly path: string) {}

  /** Cookie facts. Empty until entries() has parsed the archive. */
  observedFacts(): readonly string[] {
    return this.#facts;
  }

  async *entries(signal?: AbortSignal): AsyncIterable<ArtifactEntry> {
    const loaded = await this.#load(signal);
    this.#members.clear();
    for (const member of loaded.members) {
      abortIfNeeded(signal);
      const sealed = sealMember(member);
      this.#members.set(sealed.entry.adapterKey, sealed);
      yield sealed.entry;
    }
  }

  async open(entry: ArtifactEntry, signal?: AbortSignal): Promise<Readable> {
    abortIfNeeded(signal);
    const stored = this.#members.get(entry.adapterKey);
    if (stored === undefined || !sameArtifactEntry(entry, stored.entry))
      throw new ArtifactReaderFailure(
        "integrity",
        `PyInstaller entry was not produced by this reader: ${entry.path}`,
      );
    if (entry.kind !== "file")
      throw new ArtifactReaderFailure(
        "format",
        `PyInstaller entry is not a regular file: ${entry.path}`,
      );
    if (entry.encrypted)
      throw new ArtifactReaderFailure(
        "unavailable",
        `PYZ entry is encrypted and was not decoded: ${entry.path}`,
      );
    if (stored.bytes !== undefined) return Readable.from(stored.bytes);
    const read = stored.read;
    if (read === undefined)
      throw new ArtifactReaderFailure(
        "format",
        `PyInstaller entry has no readable bytes: ${entry.path}`,
      );
    return Readable.from(await this.#inflateMember(read, signal));
  }

  provenance(): readonly [] {
    return [];
  }

  async close(): Promise<void> {
    if (this.#owner === undefined) return;
    await this.#owner.close();
    this.#owner = undefined;
  }

  async #load(signal?: AbortSignal): Promise<LoadedArchive> {
    this.#loaded ??= this.#parse(signal);
    return this.#loaded;
  }

  async #parse(signal?: AbortSignal): Promise<LoadedArchive> {
    const handle = await this.#openHandle(signal);
    const size = (await handle.stat()).size;
    this.#budget = artifactDecompressionBudgetBytes(size);
    const cookie = await this.#cookie(handle, size);
    const toc = await this.#toc(handle, cookie);
    for (const entry of toc) this.#charge(entry.uncompressedSize);
    assertMemberRanges(toc, cookie.tocOffset);
    const images = await this.#pyzImages(handle, cookie, toc, signal);
    const magic = firstPythonMagic(images);
    const encrypted = archiveUsesEncryption(toc);
    const bytecode = await this.#bytecode(handle, cookie, toc, magic, signal);
    const members = await this.#project(
      toc,
      cookie,
      images,
      bytecode,
      magic,
      encrypted,
      signal,
    );
    this.#facts = cookieFacts(cookie);
    return { members };
  }

  async #openHandle(signal?: AbortSignal): Promise<FileHandle> {
    try {
      const handle = await openRegularFile(this.path, {
        symlinks: "reject",
        signal,
      });
      this.#owner = new OwnedFileHandle(handle);
      return handle;
    } catch (cause: unknown) {
      throw openFailure(this.path, cause);
    }
  }

  async #cookie(handle: FileHandle, size: number): Promise<PyInstallerCookie> {
    const found = await findPyInstallerCookie(handle, size);
    if (found === undefined)
      throw new ArtifactReaderFailure(
        "format",
        "PyInstaller CArchive cookie was not found",
      );
    if (!found.ok) throw failure(found.error);
    return found.value;
  }

  async #toc(
    handle: FileHandle,
    cookie: PyInstallerCookie,
  ): Promise<readonly CArchiveEntry[]> {
    const toc = await readCArchiveToc(handle, cookie);
    if (!toc.ok) throw failure(toc.error);
    return toc.value;
  }

  async #pyzImages(
    handle: FileHandle,
    cookie: PyInstallerCookie,
    toc: readonly CArchiveEntry[],
    signal: AbortSignal | undefined,
  ): Promise<ReadonlyMap<string, PyzImage>> {
    const images = new Map<string, PyzImage>();
    for (const entry of toc) {
      if (entry.typeCode !== "z") continue;
      abortIfNeeded(signal);
      const bytes = await this.#readDeclared(handle, cookie, entry);
      const parsed = parsePyzArchive(bytes);
      if (!parsed.ok) throw failure(parsed.error);
      images.set(entry.name, { archive: parsed.value, bytes });
    }
    return images;
  }

  async #bytecode(
    handle: FileHandle,
    cookie: PyInstallerCookie,
    toc: readonly CArchiveEntry[],
    magic: Buffer | undefined,
    signal: AbortSignal | undefined,
  ): Promise<ReadonlyMap<string, Buffer>> {
    const bytecode = new Map<string, Buffer>();
    if (magic === undefined) return bytecode;
    for (const entry of toc) {
      if (
        entry.typeCode !== "s" &&
        entry.typeCode !== "m" &&
        entry.typeCode !== "M"
      )
        continue;
      abortIfNeeded(signal);
      bytecode.set(entry.name, await this.#readDeclared(handle, cookie, entry));
    }
    return bytecode;
  }

  async #project(
    toc: readonly CArchiveEntry[],
    cookie: PyInstallerCookie,
    images: ReadonlyMap<string, PyzImage>,
    bytecode: ReadonlyMap<string, Buffer>,
    magic: Buffer | undefined,
    encrypted: boolean,
    signal: AbortSignal | undefined,
  ): Promise<MaterializedMember[]> {
    const members: MaterializedMember[] = [];
    for (const entry of toc) {
      abortIfNeeded(signal);
      const image = images.get(entry.name);
      if (image === undefined) {
        members.push(
          projectStoredMember(
            entry,
            cookie.archiveStart,
            magic,
            bytecode.get(entry.name),
          ),
        );
        continue;
      }
      members.push(
        projectPyzContainer(
          entry,
          cookie.archiveStart,
          image.archive,
          encrypted,
        ),
      );
      if (image.archive.kind !== "entries") continue;
      for (const item of image.archive.entries)
        members.push(
          await this.#pyzMember(
            entry,
            cookie.archiveStart,
            image.bytes,
            item,
            encrypted,
            magic,
            signal,
          ),
        );
    }
    return members;
  }

  async #pyzMember(
    entry: CArchiveEntry,
    archiveStart: number,
    image: Buffer,
    item: PyzEntry,
    encrypted: boolean,
    magic: Buffer | undefined,
    signal: AbortSignal | undefined,
  ): Promise<MaterializedMember> {
    abortIfNeeded(signal);
    if (item.namespace || encrypted)
      return projectPyzMember(
        entry,
        archiveStart,
        item,
        encrypted,
        magic,
        undefined,
      );
    if (item.length === 0)
      return projectPyzMember(
        entry,
        archiveStart,
        item,
        false,
        magic,
        Buffer.alloc(0),
      );
    const slice = image.subarray(item.offset, item.offset + item.length);
    const inflated = await inflateBounded(slice, this.#budget - this.#charged);
    if (!inflated.ok) throw failure(inflated.error);
    this.#charge(inflated.value.length);
    return projectPyzMember(
      entry,
      archiveStart,
      item,
      false,
      magic,
      inflated.value,
    );
  }

  async #readDeclared(
    handle: FileHandle,
    cookie: PyInstallerCookie,
    entry: CArchiveEntry,
  ): Promise<Buffer> {
    const compressed = await readExact(
      handle,
      cookie.archiveStart + entry.offset,
      entry.compressedSize,
    );
    if (entry.compressionFlag === 0) {
      if (compressed.length !== entry.uncompressedSize)
        throw new ArtifactReaderFailure(
          "integrity",
          `Stored CArchive member size disagrees with its table entry: ${entry.name}`,
        );
      return compressed;
    }
    const inflated = await inflateBounded(compressed, entry.uncompressedSize);
    if (!inflated.ok) throw failure(inflated.error);
    if (inflated.value.length !== entry.uncompressedSize)
      throw new ArtifactReaderFailure(
        "integrity",
        `Decompressed CArchive member size disagrees with its table entry: ${entry.name}`,
      );
    return inflated.value;
  }

  async #inflateMember(
    read: NonNullable<MaterializedMember["read"]>,
    signal: AbortSignal | undefined,
  ): Promise<Buffer> {
    abortIfNeeded(signal);
    const handle = this.#owner?.handle;
    if (handle === undefined)
      throw new ArtifactReaderFailure(
        "unavailable",
        "PyInstaller archive is closed",
      );
    const compressed = await readExact(handle, read.absolute, read.size);
    if (read.compressionFlag === 0) {
      if (compressed.length !== read.uncompressedSize)
        throw new ArtifactReaderFailure(
          "integrity",
          "Stored CArchive member size disagrees with its table entry",
        );
      return compressed;
    }
    const inflated = await inflateBounded(compressed, read.uncompressedSize);
    if (!inflated.ok) throw failure(inflated.error);
    if (inflated.value.length !== read.uncompressedSize)
      throw new ArtifactReaderFailure(
        "integrity",
        "Decompressed CArchive member size disagrees with its table entry",
      );
    return inflated.value;
  }

  #charge(bytes: number): void {
    if (
      !Number.isSafeInteger(bytes) ||
      bytes < 0 ||
      this.#charged + bytes > this.#budget
    )
      throw new ArtifactReaderFailure(
        "limit",
        `PyInstaller members declare ${String(this.#charged + Math.max(0, bytes))} uncompressed bytes, exceeding the decompression budget`,
      );
    this.#charged += bytes;
  }
}

const firstPythonMagic = (
  images: ReadonlyMap<string, PyzImage>,
): Buffer | undefined => {
  for (const image of images.values())
    if (image.archive.kind === "entries") return image.archive.pythonMagic;
  return undefined;
};

const assertMemberRanges = (
  entries: readonly CArchiveEntry[],
  tocOffset: number,
): void => {
  for (const entry of entries)
    if (
      entry.compressionFlag === 0 &&
      entry.compressedSize !== entry.uncompressedSize
    )
      throw new ArtifactReaderFailure(
        "integrity",
        `Stored CArchive member size disagrees with its table entry: ${entry.name}`,
      );
  const ranges = entries
    .filter((entry) => entry.compressedSize > 0)
    .map((entry) => ({
      name: entry.name,
      start: entry.offset,
      end: entry.offset + entry.compressedSize,
    }))
    .sort((left, right) => left.start - right.start);
  let occupied = 0;
  for (const range of ranges) {
    if (
      !Number.isSafeInteger(range.end) ||
      range.end > tocOffset ||
      range.start < occupied
    )
      throw new ArtifactReaderFailure(
        "integrity",
        `CArchive member extends outside the archive or overlaps another member: ${range.name}`,
      );
    occupied = range.end;
  }
  for (const entry of entries)
    if (entry.offset > tocOffset)
      throw new ArtifactReaderFailure(
        "format",
        `CArchive member offset is outside the archive: ${entry.name}`,
      );
};

const readExact = async (
  handle: FileHandle,
  position: number,
  size: number,
): Promise<Buffer> => {
  if (
    !Number.isSafeInteger(position) ||
    !Number.isSafeInteger(size) ||
    size < 0
  )
    throw new ArtifactReaderFailure(
      "format",
      "CArchive member range is invalid",
    );
  const bytes = Buffer.alloc(size);
  const read = await handle.read(bytes, 0, size, position);
  if (read.bytesRead !== size)
    throw new ArtifactReaderFailure(
      "format",
      "CArchive member extends outside the file",
    );
  return bytes;
};

const failure = (error: PyInstallerFailure): ArtifactReaderFailure =>
  new ArtifactReaderFailure(error.reason, error.message);

const openFailure = (path: string, cause: unknown): ArtifactReaderFailure => {
  if (cause instanceof ArtifactReaderFailure) return cause;
  if (cause instanceof RegularFileAdmissionFailure)
    return ArtifactReaderFailure.withCleanup(
      cause.cause instanceof NonRegularFileReadError
        ? new ArtifactReaderFailure(
            "format",
            `PyInstaller source is not a regular file: ${path}`,
            { cause: cause.cause },
          )
        : cause.cause,
      ArtifactReaderFailure.cleanupObservation(cause.cleanupCause, path),
    );
  if (cause instanceof NonRegularFileReadError)
    return new ArtifactReaderFailure(
      "format",
      `PyInstaller source is not a regular file: ${path}`,
      { cause },
    );
  return new ArtifactReaderFailure(
    "io",
    "PyInstaller archive could not be opened",
    {
      cause,
    },
  );
};
