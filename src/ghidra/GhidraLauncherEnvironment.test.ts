import { afterEach, expect, it, vi } from "vitest";

import * as output from "../process/ExecFileOutput.js";
import { GhidraHeadlessLauncher } from "./GhidraLauncher.js";
import { ghidraJavaLaunch } from "./GhidraJavaLaunch.js";
import { ghidraJavaEnvironment } from "./GhidraInstallation.js";

afterEach(() => vi.restoreAllMocks());

it("preserves selected Windows environment without using ComSpec to encode paths", () => {
  const environment = {
    Path: "C:\\selected\\tools",
    ComSpec: "C:\\selected\\cmd.exe",
    SystemRoot: "C:\\selected-windows",
  };
  const launcher = new GhidraHeadlessLauncher({
    environment,
    platform: "win32",
    analyzeHeadlessPath: "C:\\ghidra\\support\\analyzeHeadless.bat",
    bridgeScriptPath: "C:\\rea\\bridge.py",
  });
  environment.ComSpec = "C:\\changed\\cmd.exe";
  expect(launcher.options.environment.COMSPEC).toBe("C:\\selected\\cmd.exe");
  expect(ghidraJavaEnvironment("C:\\jdk", environment, "win32")).toMatchObject({
    PATH: "C:\\jdk\\bin;C:\\selected\\tools",
    COMSPEC: "C:\\changed\\cmd.exe",
    SYSTEMROOT: "C:\\selected-windows",
  });
});

it("passes Windows installation, JVM and analysis paths literally through LaunchSupport and direct Java argv", async () => {
  const execute = vi
    .spyOn(output, "execFileOutput")
    .mockResolvedValueOnce({
      stdout: "GHIDRA_MAXMEM=512m\n",
      stderr: "",
    })
    .mockResolvedValueOnce({
      stdout: "-Dfile.encoding=UTF8\n",
      stderr: "",
    });
  const root = "E:\\rea %PATH% & !NAME! 中文";
  const arguments_ = [
    "-scriptPath",
    `${root}\\bridge`,
    "-postScript",
    `${root}\\bridge\\ReaGhidraBridge.java`,
  ];
  const result = await ghidraJavaLaunch({
    platform: "win32",
    analyzeHeadlessPath: `${root}\\ghidra\\support\\analyzeHeadless.bat`,
    javaHome: `${root}\\jdk`,
    homeRoot: `${root}\\home`,
    tempRoot: `${root}\\tmp`,
    arguments: arguments_,
    environment: {},
    onStderr: () => {},
  });
  expect(execute).toHaveBeenCalledTimes(2);
  for (const [command, args] of execute.mock.calls) {
    expect(command).toBe(`${root}\\jdk\\bin\\java.exe`);
    expect(args).toEqual(
      expect.arrayContaining([
        `-Duser.home=${root}\\home`,
        `-Djava.io.tmpdir=${root}\\tmp`,
        "-XX:-UsePerfData",
        `${root}\\ghidra\\support\\LaunchSupport.jar`,
        `${root}\\ghidra`,
      ]),
    );
  }
  expect(result.command).toBe(`${root}\\jdk\\bin\\java.exe`);
  expect(result.arguments.slice(-arguments_.length)).toEqual(arguments_);
  expect(result.arguments).toEqual(
    expect.arrayContaining([
      `-Duser.home=${root}\\home`,
      `-Djava.io.tmpdir=${root}\\tmp`,
      "-XX:-UsePerfData",
      "-Xmx512m",
    ]),
  );
});
