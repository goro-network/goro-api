MAKEFLAGS				+=	--jobs 1
OUTPUT_DIR				+=	"output"
OUTPUT_DIR_UNITY			+=	"${OUTPUT_DIR}/unity"
OUTPUT_DIR_UNITY_ANDROID		+=	"${OUTPUT_DIR_UNITY}/android"
OUTPUT_DIR_UNITY_ANDROID_AARCH64	+=	"${OUTPUT_DIR_UNITY_ANDROID}/aarch64"
OUTPUT_DIR_UNITY_ANDROID_X86_64		+=	"${OUTPUT_DIR_UNITY_ANDROID}/x86_64"
OUTPUT_DIR_UNITY_WEBGL			+=	"${OUTPUT_DIR_UNITY}/webgl"
OUTPUT_DIR_WASM32			+=	"${OUTPUT_DIR}/wasm32"

.PHONY: all
.PHONY: clean clippy fmt test deep-clean deep-refresh prepare
.PHONY: check check-wasm32 check-unity check-unity-android check-unity-webgl
.PHONY: wasm32 unity unity-android unity-webgl
.ONESHELL: all
.ONESHELL: clean clippy fmt test deep-clean deep-refresh prepare
.ONESHELL: check check-wasm32 check-unity check-unity-android check-unity-webgl
.ONESHELL: wasm32 unity unity-android unity-webgl

all: | prepare wasm32 unity

bench:
	@echo "\033[34m\nBenchmarking...\033\n[0m"
	@cargo bench

clippy:
	@echo "\033[34m\nClippy Check...\033\n[0m"
	@cargo clippy --all -- -D warnings

fmt: | clippy
	@echo "\033[34m\nFormatting Check...\033\n[0m"
	@cargo fmt --all --check

test: | fmt
	@echo "\033[34m\nUnit & Integration Testing...\033\n[0m"
	@cargo test --all-features

check: | test
	@echo "\033[34m\nAll Check Passed!\033\n[0m"

clean:
	@echo "\033[34m\nCleaning Up...\033\n[0m"
	@cargo clean

deep-clean: | clean
	@echo "\033[34m\nDeep Clean Up...\033\n[0m"
	@rm -rf ${OUTPUT_DIR}
	@rm Cargo.lock

deep-refresh: | deep-clean check debug prepare

prepare: 
	@mkdir -p ${OUTPUT_DIR_UNITY_ANDROID_X86_64}
	@mkdir -p ${OUTPUT_DIR_UNITY_ANDROID_AARCH64}
	@mkdir -p ${OUTPUT_DIR_UNITY_WEBGL}
	@mkdir -p ${OUTPUT_DIR_WASM32}

check-unity-android:
	@echo "\033[34m\nChecking - Unity Android Library...\033\n[0m"
	@cargo check --target aarch64-linux-android --package goro-api-unity
	@cargo check --target x86_64-linux-android --package goro-api-unity

unity-android: | prepare
	@echo "\033[34m\nChecking - Unity Android Library...\033\n[0m"
	@cargo build --release --target aarch64-linux-android --package goro-api-unity
	@cp target/aarch64-linux-android/release/libgoroapi_unity.a ${OUTPUT_DIR_UNITY_ANDROID_AARCH64}/
	@cargo build --release --target x86_64-linux-android --package goro-api-unity
	@cp target/x86_64-linux-android/release/libgoroapi_unity.a ${OUTPUT_DIR_UNITY_ANDROID_X86_64}/
	@echo "\033[91m\nPlease check \"${OUTPUT_DIR_UNITY_ANDROID}\" directory\033[0m"

check-unity-webgl:
	@echo "\033[34m\nChecking - Unity WebGL Library...\033\n[0m"
	@cargo check --target wasm32-unknown-emscripten --package goro-api-unity

unity-webgl: | prepare
	@echo "\033[34m\nChecking - Unity WebGL Library...\033\n[0m"
	@cargo build --release --target wasm32-unknown-emscripten --package goro-api-unity
	@cp target/wasm32-unknown-emscripten/release/libgoroapi_unity.a ${OUTPUT_DIR_UNITY_WEBGL}/
	@echo "\033[91m\nPlease check \"${OUTPUT_DIR_UNITY_WEBGL}\" directory\033[0m"

check-unity: | check-unity-android check-unity-webgl

unity: | unity-android unity-webgl
