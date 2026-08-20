#!/usr/bin/env bash
# Reproducible Gradle entry point for this project.
#
# Two environment pins are load-bearing and the build fails without them:
#
# JAVA_HOME -> Temurin 17. Android Studio ships JDK 25 and the system JDK here
#   is 23; Gradle 8.x rejects JVM 24+, and AGP's baseline is 17.
#
# GRADLE_USER_HOME -> an isolated cache. The shared ~/.gradle/caches on this
#   machine holds a mix of Gradle 9.2.0, 8.9 and 8.11.1 artifacts written by
#   Android Studio, and the 9.x structures make 8.11.1 die during plugin
#   resolution with "FileLock.writeFile ... is null". Isolating the cache avoids
#   that without touching Studio's own setup.
#
# Usage: ./build.sh assembleDebug
set -euo pipefail

export JAVA_HOME="${JAVA_HOME_OVERRIDE:-$HOME/.jdks/jdk-17.0.20+8/Contents/Home}"
export GRADLE_USER_HOME="${GRADLE_USER_HOME_OVERRIDE:-$HOME/.gradle-satyashield}"
export ANDROID_HOME="${ANDROID_HOME:-$HOME/Library/Android/sdk}"
export ANDROID_SDK_ROOT="$ANDROID_HOME"

if [ ! -x "$JAVA_HOME/bin/java" ]; then
  echo "error: JDK 17 not found at $JAVA_HOME" >&2
  exit 1
fi

cd "$(dirname "$0")"

# Prefer a locally extracted Gradle distribution. The committed wrapper is kept
# for portability, but on a fresh GRADLE_USER_HOME it re-downloads the ~130MB
# distribution and that fetch is slow enough to time out here.
LOCAL_GRADLE="$HOME/.gradle-dist/gradle-8.11.1/bin/gradle"
if [ -x "$LOCAL_GRADLE" ]; then
  exec "$LOCAL_GRADLE" "$@"
fi
exec ./gradlew "$@"
