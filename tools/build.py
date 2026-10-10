#!/usr/bin/env python3
"""Build, check, test, and stage Bemo with Cargo and Elide (Python 3.11+)."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tomllib
import xml.etree.ElementTree as ET
import zipfile

from reports import Reports
import seam
import bitcode

ROOT = Path(__file__).resolve().parents[1]
BUILD = ROOT / "build"
VERSIONS = json.loads((ROOT / "tools/versions.json").read_text())
VERSION = (ROOT / ".version").read_text().strip()
ELIDE = os.environ.get("ELIDE", "elide")
MODULES = ("api", "ffm", "native-image", "netty")
MAVEN_GROUP = "dev.elide.bemo"
MAVEN_PATH = MAVEN_GROUP.replace(".", "/")
REPOSITORY = "https://github.com/elide-dev/bemo"


def run(*args, **kwargs):
  print("+", " ".join(map(str, args)), flush=True)
  subprocess.run(list(map(str, args)), cwd=ROOT, check=True, **kwargs)


def jar_dependency(group, artifact, version, classifier=""):
  suffix = f"-{classifier}" if classifier else ""
  path = ROOT / ".dev/dependencies/m2" / group.replace(".", "/") / artifact / version
  path /= f"{artifact}-{version}{suffix}.jar"
  if not path.is_file():
    raise RuntimeError(f"Missing pinned dependency {path}; run make deps")
  return path


def sdk():
  return [jar_dependency("org.graalvm.sdk", name, VERSIONS["graalvm_sdk"])
          for name in ("nativeimage", "word")]


def netty():
  return [jar_dependency("io.netty", name, VERSIONS["netty"]) for name in (
      "netty-common", "netty-buffer", "netty-transport", "netty-resolver", "netty-handler",
      "netty-codec-base", "netty-codec-compression", "netty-codec-http", "netty-codec-http2",
      "netty-transport-native-unix-common")]


def benchmark_netty():
  """Stock native transports are benchmark dependencies, never published dependencies."""
  system = platform.system()
  arch = {"arm64": "aarch_64", "aarch64": "aarch_64", "x86_64": "x86_64"}.get(platform.machine())
  dependencies = netty() + [jar_dependency("io.netty", "netty-tcnative-classes", VERSIONS["tcnative"])]
  dependencies += [jar_dependency("io.netty", f"netty-transport-classes-{backend}", VERSIONS["netty"])
                   for backend in ("epoll", "kqueue")]
  if system in ("Linux", "Darwin") and arch:
    backend = "epoll" if system == "Linux" else "kqueue"
    classifier = f"{'linux' if system == 'Linux' else 'osx'}-{arch}"
    dependencies += [
        jar_dependency("io.netty", f"netty-transport-native-{backend}", VERSIONS["netty"], classifier),
        jar_dependency("io.netty", "netty-tcnative-boringssl-static", VERSIONS["tcnative"], classifier)]
  return dependencies


def classpath(paths):
  return os.pathsep.join(map(str, paths))


def sources(module):
  return sorted((ROOT / "packages" / module / "src/main/java").rglob("*.java"))


def classes(module):
  return BUILD / "classes" / module


def deps():
  run(ELIDE, "install", "--slim", "--direct")


def rust(release=False, debug_info=False):
  env = dict(os.environ)
  if debug_info:
    env.update(CARGO_PROFILE_RELEASE_DEBUG="1", CARGO_PROFILE_RELEASE_STRIP="none")
  if platform.system() == "Darwin":
    env.setdefault("MACOSX_DEPLOYMENT_TARGET", "15.0")
  run("cargo", "build", "--workspace", "--locked", *(["--release"] if release else []), env=env)


def target_dir(release=False):
  metadata = subprocess.check_output(
      ["cargo", "metadata", "--no-deps", "--format-version", "1"], cwd=ROOT, text=True)
  return Path(json.loads(metadata)["target_directory"]) / ("release" if release else "debug")


def library(release=False):
  name = {"Darwin": "libbemo_ffi.dylib", "Linux": "libbemo_ffi.so", "Windows": "bemo_ffi.dll"}
  return target_dir(release) / name[platform.system()]


def jspecify():
  return jar_dependency("org.jspecify", "jspecify", VERSIONS["jspecify"])


def compile_java(output, inputs, dependencies=(), lint="all"):
  shutil.rmtree(output, ignore_errors=True)
  output.mkdir(parents=True)
  run(ELIDE, "javac", "--", "--release", VERSIONS["jvm_release"], f"-Xlint:{lint}", "-Werror",
      "-cp", classpath([*dependencies, jspecify()]), "-d", output, *inputs)


def jvm():
  deps()
  seam.generate(check=True)
  for module in MODULES:
    cp = [jspecify()] if module == "api" else [classes("api"), jspecify()]
    if module == "native-image":
      cp += sdk()
    if module == "netty":
      cp += netty()
    compile_java(classes(module), sources(module), cp)
    resources = ROOT / "packages" / module / "src/main/resources"
    if resources.is_dir():
      shutil.copytree(resources, classes(module), dirs_exist_ok=True)


def java_tool(name):
  home = os.environ.get("JAVA_HOME")
  if home:
    suffix = ".exe" if os.name == "nt" else ""
    tool = Path(home) / "bin" / (name + suffix)
    if tool.is_file():
      return tool
  found = shutil.which(name)
  if not found:
    raise RuntimeError(f"{name} is required; configure JAVA_HOME or PATH")
  return found


def test_jvm(coverage=False):
  rust()
  jvm()
  test_root = ROOT / "tests/java/dev/elide/bemo"
  output = BUILD / "tests/ffm"
  cp = [classes("api"), classes("ffm")]
  compile_java(output, [test_root / "Contract.java", test_root / "FfmContract.java"], cp)
  extra = []
  if os.name != "nt":
    incompatible = BUILD / "tests" / library().name.replace("bemo_ffi", "incompatible")
    kind = "-dynamiclib" if platform.system() == "Darwin" else "-shared"
    run(os.environ.get("CC", "cc"), kind, "-fPIC", ROOT / "tests/incompatible.c", "-o", incompatible)
    extra.append(incompatible)
  reports = Reports(BUILD / "reports/tests/jvm")
  test_bench_gzip(reports)
  agent = []
  if coverage:
    destination = BUILD / "reports/coverage/jvm"
    shutil.rmtree(destination, ignore_errors=True)
    destination.mkdir(parents=True)
    jar = jar_dependency("org.jacoco", "org.jacoco.agent", VERSIONS["jacoco"], "runtime")
    agent = [f"-javaagent:{jar}=destfile={destination / 'jacoco.exec'},append=true,includes=dev.elide.*:io.netty.handler.ssl.ApplicationProtocolSslEngine"]
  # Deliberately launch stock java, with no Elide or GraalVM SDK in the classpath.
  reports.run("FfmContract", [os.environ.get("BEMO_TEST_JAVA", java_tool("java")), *agent,
      "--enable-native-access=ALL-UNNAMED", "-ea", "-cp",
      classpath([output, *cp]), "dev.elide.bemo.FfmContract", library(), *extra], timeout=60, cwd=ROOT)
  if os.name != "nt":
    binary = BUILD / "tests/abi"
    run(os.environ.get("CC", "cc"), "-std=c11", "-Wall", "-Wextra", "-Werror",
        "-I", ROOT / "include", ROOT / "tests/abi.c", library(), "-o", binary)
    reports.run("CAbiContract", [binary], timeout=30, cwd=ROOT)
  try:
    test_transport(reports=reports, agent=agent)
  finally:
    if coverage:
      report_jvm_coverage()
  reports.finish()


def test_native_image():
  rust()
  jvm()
  test_root = ROOT / "tests/java/dev/elide/bemo"
  output = BUILD / "tests/capi"
  cp = [classes("api"), classes("native-image"), *sdk()]
  compile_java(output, [test_root / "Contract.java", test_root / "CapiContract.java"], cp)
  binary = BUILD / "tests" / ("capi-contract.exe" if os.name == "nt" else "capi-contract")
  linker = {
      "Linux": ["-H:NativeLinkerOption=-ldl", "-H:NativeLinkerOption=-lpthread", "-H:NativeLinkerOption=-lm"],
      "Darwin": [],
      "Windows": ["-H:NativeLinkerOption=ntdll.lib"],
  }[platform.system()]
  run(java_tool("native-image"), "--no-fallback", "-O0", "-cp", classpath([output, *cp]),
      f"-H:CLibraryPath={target_dir()}", f"--native-compiler-options=-I{ROOT / 'include'}",
      *linker, "dev.elide.bemo.CapiContract", binary, timeout=900)
  reports = Reports(BUILD / "reports/tests/native-image")
  reports.run("CapiContract", [binary], timeout=60, cwd=ROOT)
  test_bench_gzip(reports, native_image=True)
  test_transport(native_image=True, reports=reports)
  reports.finish()


def test_bench_gzip(reports, native_image=False):
  output = BUILD / "tests/bench"
  compile_java(output, [ROOT / "benchmarks/java/ReusableGzip.java",
                        ROOT / "tests/bench/java/ReusableGzipTest.java"])
  if native_image:
    binary = BUILD / "tests" / ("gzip-contract.exe" if os.name == "nt" else "gzip-contract")
    run(java_tool("native-image"), "--no-fallback", "-O0", "-cp", output,
        "ReusableGzipTest", binary, timeout=900)
    command = [binary]
  else:
    command = [os.environ.get("BEMO_TEST_JAVA", java_tool("java")),
               "-ea", "-cp", output, "ReusableGzipTest"]
  reports.run("ReusableGzipTest", command, timeout=30, cwd=ROOT)


def test_transport(native_image=False, reports=None, agent=()):
  output = BUILD / "tests/transport"
  cp = [classes("api"), classes("ffm"), classes("netty"), *netty()]
  compile_java(output, sorted((ROOT / "tests/transport/java").glob("*.java")),
               [*cp, classes("native-image"), *sdk()], lint="all,-restricted,-deprecation,-try,-serial")
  fixtures = ROOT / "crates/bemo/tests/fixtures"
  cert, key = fixtures / "localhost-cert.pem", fixtures / "localhost-key.pem"
  if native_image:
    binary = BUILD / "tests" / ("transport-capi.exe" if os.name == "nt" else "transport-capi")
    linker = ["-H:NativeLinkerOption=ntdll.lib"] if os.name == "nt" else []
    run(java_tool("native-image"), "--no-fallback", "--enable-monitoring=jfr", "-O0",
        "-cp", classpath([output, *cp, classes("native-image"), *sdk()]),
        f"-H:CLibraryPath={target_dir()}", f"--native-compiler-options=-I{ROOT / 'include'}",
        *linker, "CapiTlsChannelTest", binary, timeout=900)
    reports.run("CapiTlsChannelTest", [binary, cert, key], timeout=180, cwd=ROOT)
  else:
    for contract in ("FfmTransportTest", "NativeByteBufTest", "NativeChannelTest", "NativeLifecycleTest",
                     "NativeTlsChannelTest", "NativeTlsNegativeTest", "NativeTlsOrderingTest",
                     "NativeTlsClosePromiseTest", "NativeTransferTest", "NativeJfrTest",
                     "NativeReentrantCloseTest", "NativeReceiveAllocatorTest", "NativeSslEngineTest",
                     "NativeSslInteropTest", "NativeSslPolicyTest", "StandaloneTransportCheck"):
      reports.run(contract, [os.environ.get("BEMO_TEST_JAVA", java_tool("java")), *agent,
          "--enable-native-access=ALL-UNNAMED", "-ea", "-cp", classpath([output, *cp]),
          contract, library(), cert, key], timeout=90, cwd=ROOT)


def report_jvm_coverage():
  destination = BUILD / "reports/coverage/jvm"
  cli = jar_dependency("org.jacoco", "org.jacoco.cli", VERSIONS["jacoco"], "nodeps")
  args = []
  # Native Image adapter code cannot execute on a stock JVM; report it separately
  # through the C API contracts, not as misleading JVM coverage.
  for module in ("api", "ffm", "netty"):
    args.extend(["--classfiles", classes(module), "--sourcefiles", ROOT / "packages" / module / "src/main/java"])
  run(ELIDE, "java", "--", "-jar", cli, "report", destination / "jacoco.exec", *args,
      "--xml", destination / "jacoco.xml", "--html", destination / "html")


def test_rust(coverage=False):
  if coverage:
    destination = BUILD / "reports/coverage/rust"
    destination.mkdir(parents=True, exist_ok=True)
    run("cargo", "llvm-cov", "clean", "--workspace")
    try:
      run("cargo", "llvm-cov", "nextest", "--workspace", "--lib", "--tests", "--locked",
          "--profile", "ci", "--no-report")
    finally:
      run("cargo", "llvm-cov", "report", "--lcov", "--ignore-filename-regex", "/(tests|benches)/",
          "--output-path", destination / "lcov.info")
  else:
    run("cargo", "nextest", "run", "--workspace", "--lib", "--tests", "--locked", "--profile", "ci")
  run("cargo", "test", "--workspace", "--doc", "--locked")


def fmt(check=False):
  deps()
  run("cargo", "fmt", "--package", "bemo", "--package", "bemo-ffi", *(["--check"] if check else []))
  run("cargo", "fmt", "--manifest-path", "fuzz/Cargo.toml", *(["--check"] if check else []))
  run("cargo", "fmt", "--manifest-path", "benchmarks/compression/Cargo.toml", *(["--check"] if check else []))
  formatter = jar_dependency("com.google.googlejavaformat", "google-java-format",
                             VERSIONS["java_format"], "all-deps")
  java_files = [p for module in MODULES for p in sources(module)] + sorted((ROOT / "tests").rglob("*.java")) + sorted((ROOT / "benchmarks").rglob("*.java")) + sorted((ROOT / "examples").glob("*/src/**/*.java"))
  flags = ["--dry-run", "--set-exit-if-changed"] if check else ["--replace"]
  run(ELIDE, "java", "--", "-jar", formatter, *flags, *java_files)


def check():
  run(sys.executable, ROOT / "tools/test_publish_packages.py")
  run(sys.executable, ROOT / "tools/test_publish_central.py")
  run(sys.executable, ROOT / "tools/test_native_baseline.py")
  run(sys.executable, ROOT / "tools/test_bench.py")
  run(sys.executable, ROOT / "tools/test_seam.py")
  run(sys.executable, ROOT / "tools/test_bitcode.py")
  run(sys.executable, ROOT / "tools/test_setup_llvm.py")
  run(sys.executable, ROOT / "tools/generate_exports.py", "--check")
  fmt(True)
  run("cargo", "clippy", "--workspace", "--all-targets", "--locked", "--", "-D", "warnings")
  run("cargo", "clippy", "--manifest-path", "fuzz/Cargo.toml", "--all-targets", "--locked", "--", "-D", "warnings")
  run("cargo", "doc", "--workspace", "--no-deps", "--locked", env={**os.environ, "RUSTDOCFLAGS": "-D warnings"})
  cargo = tomllib.loads((ROOT / "Cargo.toml").read_text())
  if VERSION.removesuffix("-SNAPSHOT") != cargo["workspace"]["package"]["version"]:
    raise RuntimeError("Cargo.toml and .version disagree")
  if (ROOT / ".elide-version").read_text().strip() != VERSIONS["elide"]:
    raise RuntimeError("Elide version pins disagree")
  deny = subprocess.check_output(["mise", "which", "cargo-deny"], cwd=ROOT, text=True).strip()
  run(deny, "--locked", "--workspace", "check")
  jvm()
  run(sys.executable, ROOT / "tools/check_java.py")
  run(sys.executable, ROOT / "tools/verify_native_baseline.py")


def classifier():
  os_name = {"Darwin": "osx", "Linux": "linux", "Windows": "windows"}[platform.system()]
  arch = {"arm64": "aarch64", "aarch64": "aarch64", "AMD64": "x86_64", "x86_64": "x86_64"}[platform.machine()]
  libc = ""
  if os_name == "linux":
    family = platform.libc_ver()[0]
    if family != "glibc":
      raise RuntimeError("Native packaging currently validates glibc Linux only")
    libc = "-gnu"
  return f"{os_name}-{arch}{libc}"


def pom(path, artifact, dependencies):
  ns = "http://maven.apache.org/POM/4.0.0"
  ET.register_namespace("", ns)
  project = ET.Element(f"{{{ns}}}project")
  def add(parent, name, value=None):
    node = ET.SubElement(parent, f"{{{ns}}}{name}")
    node.text = value
    return node
  for name, value in (("modelVersion", "4.0.0"), ("groupId", MAVEN_GROUP), ("artifactId", artifact),
                      ("version", VERSION), ("packaging", "jar"), ("name", artifact),
                      ("description", "Bemo native transport for Netty, JVM FFM, and Native Image"),
                      ("url", REPOSITORY)):
    add(project, name, value)
  license_node = add(add(project, "licenses"), "license")
  add(license_node, "name", "Apache License, Version 2.0")
  add(license_node, "url", "https://www.apache.org/licenses/LICENSE-2.0.txt")
  developer = add(add(project, "developers"), "developer")
  add(developer, "id", "elide")
  add(developer, "name", "Elide Technologies, Inc.")
  add(developer, "url", "https://elide.dev")
  scm = add(project, "scm")
  add(scm, "url", REPOSITORY)
  add(scm, "connection", f"scm:git:{REPOSITORY}.git")
  add(scm, "developerConnection", "scm:git:ssh://git@github.com/elide-dev/bemo.git")
  distribution = add(project, "distributionManagement")
  for kind in ("repository", "snapshotRepository"):
    repository = add(distribution, kind)
    add(repository, "id", "github")
    add(repository, "name", "GitHub Packages")
    add(repository, "url", "https://maven.pkg.github.com/elide-dev/bemo")
  if dependencies:
    deps_node = add(project, "dependencies")
    for group, name, version, scope in dependencies:
      dep = add(deps_node, "dependency")
      for key, value in (("groupId", group), ("artifactId", name), ("version", version), ("scope", scope)):
        add(dep, key, value)
  ET.indent(project, space="  ")
  ET.ElementTree(project).write(path, encoding="utf-8", xml_declaration=True)


def jar(path, directory):
  run(ELIDE, "jar", "--", "--create", "--file", path,
      "--date=2026-01-01T00:00:00Z", "-C", directory, ".")


def package():
  bitcode_archive = bitcode.build()
  rust(True)
  jvm()
  stage = BUILD / "maven"
  shutil.rmtree(stage, ignore_errors=True)
  for module in MODULES:
    artifact = f"bemo-{module}"
    destination = stage / MAVEN_PATH / artifact / VERSION
    destination.mkdir(parents=True)
    prefix = destination / f"{artifact}-{VERSION}"
    metadata = classes(module) / "META-INF"
    metadata.mkdir(exist_ok=True)
    for name in ("LICENSE", "NOTICE"):
      shutil.copy2(ROOT / name, metadata / name)
    jar(f"{prefix}.jar", classes(module))
    jar(f"{prefix}-sources.jar", ROOT / "packages" / module / "src/main/java")
    docs = BUILD / "javadoc" / module
    shutil.rmtree(docs, ignore_errors=True)
    cp = [jspecify()] if module == "api" else [classes("api"), jspecify()]
    if module == "native-image":
      cp += sdk()
    if module == "netty":
      cp += netty()
    # Javadoc is run by Elide's JVM toolchain, not a second build system.
    run(ELIDE, "java", "--", "-m", "jdk.javadoc/jdk.javadoc.internal.tool.Main", "-quiet",
        "-notimestamp", "-Werror", "-Xdoclint:all,-missing", "--release", VERSIONS["jvm_release"], "-d", docs,
        "-classpath", classpath(cp) or str(classes(module)), *sources(module))
    jar(f"{prefix}-javadoc.jar", docs)
    dependencies = [("org.jspecify", "jspecify", VERSIONS["jspecify"], "compile")] if module == "api" else [(MAVEN_GROUP, "bemo-api", VERSION, "compile")]
    if module == "native-image":
      dependencies += [("org.graalvm.sdk", name, VERSIONS["graalvm_sdk"], "provided")
                       for name in ("nativeimage", "word")]
    if module == "netty":
      dependencies += [("io.netty", name, VERSIONS["netty"], "compile") for name in (
          "netty-transport", "netty-handler", "netty-codec-http2", "netty-transport-native-unix-common")]
    pom(f"{prefix}.pom", artifact, dependencies)
  # Attach separate dynamic and static native classifiers; keep base JARs portable.
  static_name = "bemo_ffi.lib" if os.name == "nt" else "libbemo_ffi.a"
  for module, binary in (("ffm", library(True)), ("native-image", target_dir(True) / static_name)):
    native = BUILD / "native-resources" / module
    shutil.rmtree(native, ignore_errors=True)
    resource = native / "META-INF/native" / classifier()
    resource.mkdir(parents=True)
    shutil.copy2(binary, resource)
    shutil.copy2(ROOT / "include/bemo.h", resource)
    shutil.copy2(ROOT / "include/elide_transport.h", resource)
    for name in ("LICENSE", "NOTICE"):
      shutil.copy2(ROOT / name, native / "META-INF" / name)
    prefix = stage / MAVEN_PATH / f"bemo-{module}" / VERSION / f"bemo-{module}-{VERSION}"
    jar(f"{prefix}-{classifier()}.jar", native)
  variant = classifier() + "-thinlto"
  native = BUILD / "native-resources/thinlto"
  shutil.rmtree(native, ignore_errors=True)
  resource = native / "META-INF/native" / classifier()
  resource.mkdir(parents=True)
  for binary in (bitcode_archive, bitcode.DIRECTORY / "manifest.json"):
    shutil.copy2(binary, resource)
  for name in ("bemo.h", "elide_transport.h"):
    shutil.copy2(ROOT / "include" / name, resource)
  for name in ("seam.json", "seam.abi", "seam.ll"):
    shutil.copy2(seam.output() / name, resource)
  for name in ("LICENSE", "NOTICE"):
    shutil.copy2(ROOT / name, native / "META-INF" / name)
  prefix = stage / MAVEN_PATH / "bemo-native-image" / VERSION / f"bemo-native-image-{VERSION}"
  jar(f"{prefix}-{variant}.jar", native)
  for path in sorted(stage.rglob("*")):
    if path.is_file():
      for algorithm in ("md5", "sha1", "sha256", "sha512"):
        digest = hashlib.new(algorithm, path.read_bytes()).hexdigest()
        Path(f"{path}.{algorithm}").write_text(digest + "\n")
  bundle = BUILD / f"bemo-{VERSION}-{classifier()}-unsigned.zip"
  with zipfile.ZipFile(bundle, "w", zipfile.ZIP_DEFLATED) as archive:
    for path in sorted(stage.rglob("*")):
      if path.is_file():
        archive.write(path, path.relative_to(stage))
  print(f"Staged unsigned Maven repository: {stage}\nBundle: {bundle}")


def main():
  parser = argparse.ArgumentParser(description=__doc__)
  parser.add_argument("task", choices=("deps", "build", "jvm", "test", "test-jvm", "test-native-image",
                                       "check", "fmt", "fmt-check", "package", "clean", "test-rust", "coverage-rust", "coverage-jvm"))
  task = parser.parse_args().task
  if task == "deps": deps()
  elif task == "build": rust(); jvm()
  elif task == "jvm": jvm()
  elif task == "test":
    test_rust()
    run(sys.executable, ROOT / "tools/test_git_dependency.py")
    test_jvm()
  elif task == "test-rust": test_rust()
  elif task == "coverage-rust": test_rust(coverage=True)
  elif task == "coverage-jvm": test_jvm(coverage=True)
  elif task == "test-jvm": test_jvm()
  elif task == "test-native-image": test_native_image()
  elif task == "check": check()
  elif task == "fmt": fmt()
  elif task == "fmt-check": fmt(True)
  elif task == "package": package()
  elif task == "clean":
    shutil.rmtree(BUILD, ignore_errors=True)
    run("cargo", "clean")


if __name__ == "__main__":
  try:
    main()
  except (subprocess.CalledProcessError, subprocess.TimeoutExpired, RuntimeError, OSError) as failure:
    print(f"error: {failure}", file=sys.stderr)
    sys.exit(1)
