import { createHash } from "node:crypto";
import { readFile, stat, writeFile } from "node:fs/promises";
import { join } from "node:path";

import { expect, it, vi } from "vitest";

import { ArtifactReaderFailure } from "../ArtifactReader.js";
import { OwnedFileHandle } from "../../filesystem/OwnedFileHandle.js";
import { materializeArtifactInventory } from "../../../tests/fixtures/artifactInventory.js";
import { scanCanonicalArtifactInventory } from "../../../tests/fixtures/artifactInventory.js";
import { createTestTempDirectory } from "../../../tests/fixtures/temporaryDirectory.js";
import { PyInstallerArtifactReader } from "../PyInstallerArtifactReader.js";
import {
  RECONSTRUCTED_PYTHON_HEADER_LIMITATION,
  reconstructedPycHeader,
} from "./PythonBytecode.js";
import {
  PYTHON_39_MAGIC,
  cArchiveExecutable,
  cookieRangeOutsideFile,
  pyzArchive,
  type CArchiveFixtureMember,
} from "./CArchive.fixture.js";

const sha256 = (bytes: Buffer): string =>
  createHash("sha256").update(bytes).digest("hex");

const derived = (payload: Buffer): Buffer =>
  Buffer.concat([reconstructedPycHeader(PYTHON_39_MAGIC), payload]);

const writeArchive = async (name: string, bytes: Buffer): Promise<string> => {
  const directory = await createTestTempDirectory("rea-pyinstaller-");
  const path = join(directory, name);
  await writeFile(path, bytes);
  return path;
};

const sampleMembers = (
  script: Buffer,
  stored: Buffer,
  pyz: Buffer,
): CArchiveFixtureMember[] => [
  { name: "hello", typeCode: "s", payload: script, compress: true },
  { name: "data.bin", typeCode: "x", payload: stored, compress: false },
  { name: "PYZ.pyz", typeCode: "z", payload: pyz, compress: false },
  {
    name: "pyi-contents-directory _internal",
    typeCode: "o",
    payload: Buffer.alloc(0),
    compress: false,
  },
];

it("inventories a 2.1 archive, nested PYZ modules, and derived bytecode", async () => {
  const script = Buffer.from("print('hi')");
  const stored = Buffer.from("stored-data");
  const moduleBody = Buffer.from("module-body");
  const path = await writeArchive(
    "hello",
    cArchiveExecutable({
      layout: "2.1",
      pythonVersion: 314,
      pythonLibrary: "libpython3.14.dylib",
      trailer: Buffer.from("signature"),
      members: sampleMembers(
        script,
        stored,
        pyzArchive({
          magic: PYTHON_39_MAGIC,
          modules: [
            { name: "json.decoder", typeCode: 0, body: moduleBody },
            { name: "pkg", typeCode: 1, body: moduleBody },
            { name: "ns", typeCode: 3, body: Buffer.alloc(0) },
          ],
        }),
      ),
    }),
  );
  const snapshot = await scanCanonicalArtifactInventory(path);
  expect(snapshot.manifest.root_format).toBe("pyinstaller");
  expect(snapshot.coverage_status).toBe("complete");
  const root = snapshot.occurrences.find(
    (occurrence) => occurrence.logical_path === ".",
  );
  expect(root).toMatchObject({ artifact_kind: "container" });
  expect(root?.limitations).toEqual(
    expect.arrayContaining([
      "PyInstaller CArchive layout 2.1.",
      "Python version 314 (3.14).",
      "Python library libpython3.14.dylib.",
    ]),
  );
  const hello = snapshot.occurrences.find(
    (occurrence) => occurrence.logical_path === "hello",
  );
  expect(hello?.limitations).toEqual(
    expect.arrayContaining([
      "PyInstaller type code s.",
      "PyInstaller compression flag 1.",
      RECONSTRUCTED_PYTHON_HEADER_LIMITATION,
      `Uncompressed sha256 ${sha256(script)}.`,
    ]),
  );
  expect(
    snapshot.nodes.find((node) => node.sha256 === sha256(derived(script))),
  ).toMatchObject({ size: derived(script).length });
  expect(
    snapshot.nodes.find((node) => node.sha256 === sha256(stored)),
  ).toBeDefined();
  expect(
    snapshot.occurrences.map((occurrence) => occurrence.logical_path),
  ).toEqual(
    expect.arrayContaining([
      "hello",
      "data.bin",
      "PYZ.pyz",
      "PYZ.pyz/json/decoder.pyc",
      "PYZ.pyz/pkg/__init__.pyc",
      "PYZ.pyz/ns",
      "pyi-contents-directory _internal",
    ]),
  );
  expect(
    snapshot.occurrences.find(
      (occurrence) => occurrence.logical_path === "PYZ.pyz",
    )?.entry_kind,
  ).toBe("directory");
  const scriptEdge = snapshot.edges.find(
    (edge) => edge.occurrence_id === hello?.occurrence_id,
  );
  expect(scriptEdge?.relation).toBe("derived-from");
});

it("records a 2.0 cookie without a Python library name", async () => {
  const path = await writeArchive(
    "legacy",
    cArchiveExecutable({
      layout: "2.0",
      pythonVersion: 307,
      members: [
        {
          name: "hello",
          typeCode: "s",
          payload: Buffer.from("print"),
          compress: false,
        },
      ],
    }),
  );
  const snapshot = await scanCanonicalArtifactInventory(path);
  const root = snapshot.occurrences.find(
    (occurrence) => occurrence.logical_path === ".",
  );
  expect(root?.limitations).toEqual(
    expect.arrayContaining([
      "PyInstaller CArchive layout 2.0.",
      "Python version 307 (3.7).",
      "Python library is unknown.",
    ]),
  );
});

it("extracts derived members into the safe output tree", async () => {
  const script = Buffer.from("print('hi')");
  const path = await writeArchive(
    "hello",
    cArchiveExecutable({
      layout: "2.1",
      pythonVersion: 309,
      pythonLibrary: "libpython3.9.so",
      members: sampleMembers(
        script,
        Buffer.from("stored"),
        pyzArchive({
          magic: PYTHON_39_MAGIC,
          modules: [
            { name: "app", typeCode: 0, body: Buffer.from("app-body") },
          ],
        }),
      ),
    }),
  );
  const snapshot = await scanCanonicalArtifactInventory(path);
  const directory = await createTestTempDirectory("rea-pyinstaller-out-");
  const output = join(directory, "extracted");
  const extracted = await materializeArtifactInventory(
    {
      inputPath: path,
      inputFormat: "elf",
      outputRoot: output,
      environment: process.env,
      integrityPolicy: "fail",
    },
    path,
    snapshot,
  );
  expect(await readFile(join(output, "hello"))).toEqual(derived(script));
  expect(
    extracted.artifacts.find((artifact) => artifact.relative_path === "hello")
      ?.sha256,
  ).toBe(sha256(derived(script)));
  expect(await readFile(join(output, "PYZ.pyz", "app.pyc"))).toEqual(
    derived(Buffer.from("app-body")),
  );
});

it("reports encrypted PYZ entries and refuses to extract them", async () => {
  const path = await writeArchive(
    "encrypted",
    cArchiveExecutable({
      layout: "2.1",
      pythonVersion: 309,
      pythonLibrary: "libpython3.9.so",
      members: [
        {
          name: "pyimod00_crypto_key",
          typeCode: "m",
          payload: Buffer.from("key"),
          compress: false,
        },
        {
          name: "PYZ.pyz",
          typeCode: "z",
          payload: pyzArchive({
            magic: PYTHON_39_MAGIC,
            modules: [
              { name: "secret", typeCode: 0, body: Buffer.from("hidden") },
            ],
          }),
          compress: false,
        },
      ],
    }),
  );
  const snapshot = await scanCanonicalArtifactInventory(path);
  expect(
    snapshot.occurrences.find(
      (occurrence) => occurrence.logical_path === "PYZ.pyz/secret.pyc",
    ),
  ).toMatchObject({
    encrypted: true,
    hash_status: "unavailable",
  });
  const directory = await createTestTempDirectory("rea-pyinstaller-out-");
  await expect(
    materializeArtifactInventory(
      {
        inputPath: path,
        inputFormat: "elf",
        outputRoot: join(directory, "extracted"),
        environment: process.env,
        integrityPolicy: "fail",
      },
      path,
      snapshot,
    ),
  ).rejects.toThrow(/encrypted/u);
});

it("leaves an unsupported PYZ magic as one opaque member", async () => {
  const path = await writeArchive(
    "opaque",
    cArchiveExecutable({
      layout: "2.1",
      pythonVersion: 314,
      pythonLibrary: "libpython3.14.dylib",
      members: [
        {
          name: "PYZ.pyz",
          typeCode: "z",
          payload: pyzArchive({
            magic: Buffer.alloc(4),
            modules: [{ name: "app", typeCode: 0, body: Buffer.from("app") }],
          }),
          compress: false,
        },
      ],
    }),
  );
  const snapshot = await scanCanonicalArtifactInventory(path);
  const pyz = snapshot.occurrences.find(
    (occurrence) => occurrence.logical_path === "PYZ.pyz",
  );
  expect(pyz).toMatchObject({ entry_kind: "file" });
  expect(pyz?.limitations.join(" ")).toContain("left opaque");
  expect(
    snapshot.occurrences.some((occurrence) =>
      occurrence.logical_path.endsWith(".pyc"),
    ),
  ).toBe(false);
});

it("reads children of a zlib-compressed PYZ", async () => {
  const body = Buffer.from("compressed-child");
  const path = await writeArchive(
    "compressed-pyz",
    cArchiveExecutable({
      layout: "2.1",
      pythonVersion: 309,
      pythonLibrary: "libpython3.9.so",
      members: [
        {
          name: "PYZ.pyz",
          typeCode: "z",
          payload: pyzArchive({
            magic: PYTHON_39_MAGIC,
            modules: [{ name: "child", typeCode: 0, body }],
          }),
          compress: true,
        },
      ],
    }),
  );
  const snapshot = await scanCanonicalArtifactInventory(path);
  expect(
    snapshot.nodes.find((node) => node.sha256 === sha256(derived(body))),
  ).toMatchObject({ size: derived(body).length });
});

it("rejects a truncated table of contents", async () => {
  const path = await writeArchive(
    "truncated",
    cArchiveExecutable({
      layout: "2.1",
      pythonVersion: 314,
      pythonLibrary: "libpython3.14.dylib",
      members: [],
      tocBytes: Buffer.concat([Buffer.from([0, 0, 0, 64]), Buffer.alloc(16)]),
    }),
  );
  await expect(scanCanonicalArtifactInventory(path)).rejects.toBeInstanceOf(
    ArtifactReaderFailure,
  );
  await expect(scanCanonicalArtifactInventory(path)).rejects.toMatchObject({
    reason: "format",
  });
});

it("rejects a cookie whose package range is outside the file", async () => {
  const path = await writeArchive("outside", cookieRangeOutsideFile());
  const reader = new PyInstallerArtifactReader(path);
  await expect(async () => {
    for await (const entry of reader.entries()) void entry;
  }).rejects.toMatchObject({
    reason: "format",
    message: expect.stringContaining("outside the file"),
  });
  await reader.close();
});

it("rejects a member whose declared size exceeds the decompression budget", async () => {
  const path = await writeArchive(
    "bomb",
    cArchiveExecutable({
      layout: "2.1",
      pythonVersion: 314,
      pythonLibrary: "libpython3.14.dylib",
      members: [
        {
          name: "bomb.bin",
          typeCode: "b",
          payload: Buffer.alloc(0),
          compress: true,
          declaredUncompressedSize: 300 * 1024 * 1024,
        },
      ],
    }),
  );
  await expect(scanCanonicalArtifactInventory(path)).rejects.toMatchObject({
    reason: "limit",
  });
});

it("rejects a zlib member that expands past its declared size", async () => {
  const path = await writeArchive(
    "expand",
    cArchiveExecutable({
      layout: "2.1",
      pythonVersion: 314,
      pythonLibrary: "libpython3.14.dylib",
      members: [
        {
          name: "expand.bin",
          typeCode: "b",
          payload: Buffer.from("hello world hello world"),
          compress: true,
          declaredUncompressedSize: 4,
        },
      ],
    }),
  );
  await expect(scanCanonicalArtifactInventory(path)).rejects.toMatchObject({
    reason: "limit",
  });
});

it("reads a compressed member whose uncompressed size is zero", async () => {
  const path = await writeArchive(
    "empty-compressed",
    cArchiveExecutable({
      layout: "2.1",
      pythonVersion: 309,
      pythonLibrary: "libpython3.9.so",
      members: [
        {
          name: "empty.bin",
          typeCode: "x",
          payload: Buffer.alloc(0),
          compress: true,
        },
        {
          name: "empty.py",
          typeCode: "s",
          payload: Buffer.alloc(0),
          compress: true,
        },
        {
          name: "PYZ.pyz",
          typeCode: "z",
          payload: pyzArchive({
            magic: PYTHON_39_MAGIC,
            modules: [{ name: "app", typeCode: 0, body: Buffer.from("app") }],
          }),
          compress: false,
        },
      ],
    }),
  );
  const snapshot = await scanCanonicalArtifactInventory(path);
  expect(
    snapshot.nodes.find((node) => node.sha256 === sha256(Buffer.alloc(0))),
  ).toMatchObject({ size: 0 });
  expect(
    snapshot.nodes.find(
      (node) => node.sha256 === sha256(derived(Buffer.alloc(0))),
    ),
  ).toMatchObject({ size: derived(Buffer.alloc(0)).length });

  const expanded = await writeArchive(
    "zero-declared",
    cArchiveExecutable({
      layout: "2.1",
      pythonVersion: 309,
      pythonLibrary: "libpython3.9.so",
      members: [
        {
          name: "expand.bin",
          typeCode: "x",
          payload: Buffer.from("x"),
          compress: true,
          declaredUncompressedSize: 0,
        },
      ],
    }),
  );
  await expect(scanCanonicalArtifactInventory(expanded)).rejects.toMatchObject({
    reason: "limit",
  });
});

it("preserves an uppercase Z ZIP member as a readable file", async () => {
  const zip = Buffer.from("PK\u0003\u0004zip-member");
  const path = await writeArchive(
    "zip-member",
    cArchiveExecutable({
      layout: "2.1",
      pythonVersion: 309,
      pythonLibrary: "libpython3.9.so",
      members: [
        {
          name: "payload.zip",
          typeCode: "Z",
          payload: zip,
          compress: false,
        },
      ],
    }),
  );
  const snapshot = await scanCanonicalArtifactInventory(path);
  expect(
    snapshot.occurrences.map((occurrence) => occurrence.logical_path).sort(),
  ).toEqual([".", "payload.zip"]);
  expect(
    snapshot.occurrences.find(
      (occurrence) => occurrence.logical_path === "payload.zip",
    ),
  ).toMatchObject({
    entry_kind: "file",
    limitations: expect.arrayContaining(["PyInstaller type code Z."]),
  });
  expect(
    snapshot.nodes.find((node) => node.sha256 === sha256(zip)),
  ).toMatchObject({ size: zip.length });
});

it("keeps a PYZ data entry resource path", async () => {
  const body = Buffer.from('{"enabled":true}');
  const path = await writeArchive(
    "pyz-data",
    cArchiveExecutable({
      layout: "2.1",
      pythonVersion: 309,
      pythonLibrary: "libpython3.9.so",
      members: [
        {
          name: "PYZ.pyz",
          typeCode: "z",
          payload: pyzArchive({
            magic: PYTHON_39_MAGIC,
            modules: [{ name: "pkg/config.json", typeCode: 2, body }],
          }),
          compress: false,
        },
      ],
    }),
  );
  const snapshot = await scanCanonicalArtifactInventory(path);
  expect(
    snapshot.occurrences.map((occurrence) => occurrence.logical_path).sort(),
  ).toEqual([".", "PYZ.pyz", "PYZ.pyz/pkg/config.json"]);
  expect(
    snapshot.occurrences.find(
      (occurrence) => occurrence.logical_path === "PYZ.pyz/pkg/config.json",
    ),
  ).toMatchObject({ entry_kind: "file" });
  expect(
    snapshot.nodes.find((node) => node.sha256 === sha256(body)),
  ).toMatchObject({ size: body.length });
});

it("retains the file owner after a failed close", async () => {
  const path = await writeArchive(
    "close-owner",
    cArchiveExecutable({
      layout: "2.1",
      pythonVersion: 309,
      pythonLibrary: "libpython3.9.so",
      members: [
        {
          name: "data.bin",
          typeCode: "x",
          payload: Buffer.from("data"),
          compress: false,
        },
      ],
    }),
  );
  const reader = new PyInstallerArtifactReader(path);
  for await (const entry of reader.entries()) void entry;
  const originalClose = OwnedFileHandle.prototype.close;
  const owners: OwnedFileHandle[] = [];
  const closeFailure = new Error("close failed");
  let attempts = 0;
  const close = vi
    .spyOn(OwnedFileHandle.prototype, "close")
    .mockImplementation(async function (this: OwnedFileHandle) {
      owners.push(this);
      attempts += 1;
      if (attempts === 1) throw closeFailure;
      await originalClose.call(this);
    });
  try {
    await expect(reader.close()).rejects.toBe(closeFailure);
    await reader.close();
    expect(attempts).toBe(2);
    expect(owners[0]).toBe(owners[1]);
  } finally {
    close.mockRestore();
    await reader.close();
  }
});

it("inventories and extracts a Windows member name under its canonical path", async () => {
  const storedName = String.raw`pkg\data.bin`;
  const pyzName = String.raw`res\icon.bin`;
  const payload = Buffer.from("nested-bytes");
  const icon = Buffer.from("icon-bytes");
  const path = await writeArchive(
    "windows",
    cArchiveExecutable({
      layout: "2.1",
      pythonVersion: 309,
      pythonLibrary: "python39.dll",
      members: [
        { name: storedName, typeCode: "x", payload, compress: false },
        {
          name: "PYZ.pyz",
          typeCode: "z",
          payload: pyzArchive({
            magic: PYTHON_39_MAGIC,
            modules: [{ name: pyzName, typeCode: 2, body: icon }],
          }),
          compress: false,
        },
      ],
    }),
  );
  const snapshot = await scanCanonicalArtifactInventory(path);
  const member = snapshot.occurrences.find(
    (occurrence) => occurrence.logical_path === "pkg/data.bin",
  );
  const resource = snapshot.occurrences.find(
    (occurrence) => occurrence.logical_path === "PYZ.pyz/res/icon.bin",
  );
  expect(member?.limitations).toContain(
    `Stored PyInstaller member name: ${JSON.stringify(storedName)}.`,
  );
  expect(resource?.limitations).toContain(
    `Stored PyInstaller member name: ${JSON.stringify(pyzName)}.`,
  );
  const directory = await createTestTempDirectory("rea-pyinstaller-out-");
  const output = join(directory, "extracted");
  await materializeArtifactInventory(
    {
      inputPath: path,
      inputFormat: "elf",
      outputRoot: output,
      environment: process.env,
      integrityPolicy: "fail",
    },
    path,
    snapshot,
  );
  expect(await readFile(join(output, "pkg", "data.bin"))).toEqual(payload);
  expect(await readFile(join(output, "PYZ.pyz", "res", "icon.bin"))).toEqual(
    icon,
  );
});

it("rejects a stored member whose declared size disagrees with its bytes", async () => {
  const path = await writeArchive(
    "stored-size",
    cArchiveExecutable({
      layout: "2.1",
      pythonVersion: 309,
      pythonLibrary: "python39.dll",
      members: [
        {
          name: "data.bin",
          typeCode: "x",
          payload: Buffer.from("abcd"),
          compress: false,
          declaredUncompressedSize: 0,
        },
      ],
    }),
  );
  await expect(scanCanonicalArtifactInventory(path)).rejects.toMatchObject({
    reason: "integrity",
    message: expect.stringContaining(
      "Stored CArchive member size disagrees with its table entry",
    ),
  });
});

it("keeps compressed member spans on the physical extent or unknown", async () => {
  const payload = Buffer.alloc(10_000, 0x61);
  const path = await writeArchive(
    "compressed-span",
    cArchiveExecutable({
      layout: "2.1",
      pythonVersion: 309,
      pythonLibrary: "python39.dll",
      members: [
        { name: "payload.bin", typeCode: "x", payload, compress: true },
        {
          name: "PYZ.pyz",
          typeCode: "z",
          payload: pyzArchive({
            magic: PYTHON_39_MAGIC,
            modules: [{ name: "app", typeCode: 0, body: payload }],
          }),
          compress: false,
        },
      ],
    }),
  );
  const snapshot = await scanCanonicalArtifactInventory(path);
  const fileSize = (await stat(path)).size;
  expect(fileSize).toBeLessThan(payload.length);
  for (const logicalPath of ["payload.bin", "PYZ.pyz/app.pyc"]) {
    const occurrence = snapshot.occurrences.find(
      (candidate) => candidate.logical_path === logicalPath,
    );
    expect(occurrence?.declared_size).toBeGreaterThan(fileSize);
    expect(occurrence?.compressed_size ?? fileSize).toBeLessThan(
      occurrence?.declared_size ?? 0,
    );
    const span = occurrence?.source_location;
    if (span === null || span === undefined) {
      expect(span).toBeNull();
      continue;
    }
    expect(span.length).toBe(occurrence?.compressed_size);
    expect(span.offset + span.length).toBeLessThanOrEqual(fileSize);
  }
  for (const occurrence of snapshot.occurrences) {
    const span = occurrence.source_location;
    if (span === null) continue;
    expect(span.offset + span.length).toBeLessThanOrEqual(fileSize);
  }
});
