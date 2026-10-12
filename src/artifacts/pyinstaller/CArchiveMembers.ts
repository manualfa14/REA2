import { createHash } from "node:crypto";

import { copyArtifactEntry, type ArtifactEntry } from "../ArtifactReader.js";
import type { CArchiveEntry, PyInstallerCookie } from "./CArchiveLayout.js";
import type { PyzArchive, PyzEntry } from "./PyzArchive.js";
import {
  RECONSTRUCTED_PYTHON_HEADER_LIMITATION,
  reconstructedPycHeader,
} from "./PythonBytecode.js";
import { formatPythonCookieVersion } from "./PythonBytecode.js";

const CRYPTO_KEY_NAME = "pyimod00_crypto_key";

/** Bytes the reader returns for one inventoried file, when already materialized. */
export interface MaterializedMember {
  readonly entry: ArtifactEntry;
  readonly bytes: Buffer | undefined;
  readonly read:
    | {
        readonly absolute: number;
        readonly size: number;
        readonly compressionFlag: number;
        readonly uncompressedSize: number;
      }
    | undefined;
}

/** Facts observed from the cookie. The root occurrence records them. */
export const cookieFacts = (cookie: PyInstallerCookie): readonly string[] => [
  `PyInstaller CArchive layout ${cookie.layout}.`,
  `Python version ${formatPythonCookieVersion(cookie.pythonVersion)}.`,
  cookie.pythonLibrary === null
    ? "Python library is unknown."
    : `Python library ${cookie.pythonLibrary}.`,
];

export const archiveUsesEncryption = (
  entries: readonly CArchiveEntry[],
): boolean => entries.some((entry) => entry.name === CRYPTO_KEY_NAME);

export const projectStoredMember = (
  entry: CArchiveEntry,
  archiveStart: number,
  pythonMagic: Buffer | undefined,
  bytes: Buffer | undefined,
): MaterializedMember => {
  const header =
    pythonMagic !== undefined && isBytecodeType(entry.typeCode)
      ? reconstructedPycHeader(pythonMagic)
      : undefined;
  const limitations = memberLimitations(entry.typeCode, entry.compressionFlag);
  if (header !== undefined && bytes !== undefined) {
    limitations.push(RECONSTRUCTED_PYTHON_HEADER_LIMITATION);
    limitations.push(`Uncompressed sha256 ${sha256(bytes)}.`);
  }
  return {
    entry: fileEntry({
      path: entry.name,
      declaredSize: bytes === undefined ? entry.uncompressedSize : bytes.length,
      compressedSize: entry.compressedSize,
      byteOffset: archiveStart + entry.offset,
      limitations,
      adapterKey: `carchive:${entry.name}`,
    }),
    bytes:
      header === undefined || bytes === undefined
        ? undefined
        : Buffer.concat([header, bytes]),
    read:
      bytes === undefined
        ? {
            absolute: archiveStart + entry.offset,
            size: entry.compressedSize,
            compressionFlag: entry.compressionFlag,
            uncompressedSize: entry.uncompressedSize,
          }
        : undefined,
  };
};

export const projectPyzContainer = (
  entry: CArchiveEntry,
  archiveStart: number,
  archive: PyzArchive,
  encrypted: boolean,
): MaterializedMember => {
  if (archive.kind === "opaque")
    return {
      entry: fileEntry({
        path: entry.name,
        declaredSize: entry.uncompressedSize,
        compressedSize: entry.compressedSize,
        byteOffset: archiveStart + entry.offset,
        limitations: [
          ...memberLimitations(entry.typeCode, entry.compressionFlag),
          archive.limitation,
        ],
        adapterKey: `carchive:${entry.name}`,
      }),
      bytes: undefined,
      read: {
        absolute: archiveStart + entry.offset,
        size: entry.compressedSize,
        compressionFlag: entry.compressionFlag,
        uncompressedSize: entry.uncompressedSize,
      },
    };
  return {
    entry: {
      path: entry.name,
      kind: "directory",
      declaredSize: entry.uncompressedSize,
      compressedSize: entry.compressedSize,
      executable: false,
      encrypted: false,
      byteOffset: archiveStart + entry.offset,
      declaredSha256: null,
      unpacked: false,
      limitations: [
        ...memberLimitations(entry.typeCode, entry.compressionFlag),
        `PyInstaller PYZ sha256 ${archive.sha256}.`,
        ...(encrypted
          ? ["PYZ entries are encrypted and were not decoded."]
          : []),
      ],
      adapterKey: `carchive:${entry.name}`,
    },
    bytes: undefined,
    read: undefined,
  };
};

export const projectPyzMember = (
  container: CArchiveEntry,
  archiveStart: number,
  item: PyzEntry,
  encrypted: boolean,
  pythonMagic: Buffer | undefined,
  inflated: Buffer | undefined,
): MaterializedMember => {
  const path = pyzPath(container.name, item);
  if (item.namespace)
    return {
      entry: {
        path,
        kind: "directory",
        declaredSize: 0,
        compressedSize: 0,
        executable: false,
        encrypted: false,
        byteOffset: null,
        declaredSha256: null,
        unpacked: false,
        limitations: [
          "PyInstaller PYZ type 3.",
          "Namespace package has no bytecode.",
        ],
        adapterKey: `pyz:${path}`,
      },
      bytes: undefined,
      read: undefined,
    };
  const header =
    !encrypted &&
    pythonMagic !== undefined &&
    (item.typeCode === 0 || item.typeCode === 1)
      ? reconstructedPycHeader(pythonMagic)
      : undefined;
  const limitations = [
    `PyInstaller PYZ type ${String(item.typeCode)}.`,
    "PyInstaller compression flag 1.",
  ];
  if (encrypted)
    limitations.push("PYZ entry is encrypted and was not decoded.");
  if (header !== undefined && inflated !== undefined) {
    limitations.push(RECONSTRUCTED_PYTHON_HEADER_LIMITATION);
    limitations.push(`Uncompressed sha256 ${sha256(inflated)}.`);
  }
  const stored = container.compressionFlag === 0;
  const body =
    inflated === undefined
      ? undefined
      : header === undefined
        ? inflated
        : Buffer.concat([header, inflated]);
  return {
    entry: fileEntry({
      path,
      declaredSize: inflated === undefined ? item.length : inflated.length,
      compressedSize: item.length,
      byteOffset: stored ? archiveStart + container.offset + item.offset : null,
      encrypted,
      limitations,
      adapterKey: `pyz:${path}`,
    }),
    bytes: body,
    read: undefined,
  };
};

const pyzPath = (container: string, item: PyzEntry): string => {
  const dotted = item.name.replaceAll(".", "/");
  if (item.namespace) return `${container}/${dotted}`;
  if (item.package) return `${container}/${dotted}/__init__.pyc`;
  return `${container}/${dotted}.pyc`;
};

const isBytecodeType = (typeCode: string): boolean =>
  typeCode === "s" || typeCode === "m" || typeCode === "M";

const memberLimitations = (
  typeCode: string,
  compressionFlag: number,
): string[] => [
  `PyInstaller type code ${typeCode}.`,
  `PyInstaller compression flag ${String(compressionFlag)}.`,
];

const fileEntry = (input: {
  readonly path: string;
  readonly declaredSize: number;
  readonly compressedSize: number;
  readonly byteOffset: number | null;
  readonly limitations: readonly string[];
  readonly adapterKey: string;
  readonly encrypted?: boolean;
}): ArtifactEntry => ({
  path: input.path,
  kind: "file",
  declaredSize: input.declaredSize,
  compressedSize: input.compressedSize,
  executable: false,
  encrypted: input.encrypted === true,
  byteOffset: input.byteOffset,
  declaredSha256: null,
  unpacked: false,
  limitations: input.limitations,
  adapterKey: input.adapterKey,
});

const sha256 = (bytes: Buffer): string =>
  createHash("sha256").update(bytes).digest("hex");

/** Stable entry stored for a later open(). */
export const sealMember = (member: MaterializedMember): MaterializedMember => ({
  ...member,
  entry: copyArtifactEntry(member.entry),
});
