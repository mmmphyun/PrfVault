# Wasm C-ABI 메모리 관리 및 C 언어 1:1 기계적 동작 대조 명세

## 1. 개요 및 배경 (Problem Statement)

PrfVault의 핵심 보안 목표는 **브라우저 런타임 환경에서 암호화 마스터 키 및 비밀번호 평문이 메모리에 영구 잔류하는 것을 방지(Anti-Memory Leakage)**하는 것이다.

### 1.1 V8 JavaScript 런타임의 한계
* JavaScript/TypeScript 런타임(V8 엔진)은 가비지 컬렉션(GC) 기반 언어다.
* 변수 참조가 끊어져도 OS 힙에 할당된 버퍼를 개발자가 명시적으로 `0x00`으로 덮어쓸(Overwrite) 수 있는 권한이 없다.
* GC가 작동하기 전까지 수십 초~수 분 동안 마스터 키와 평문 바이트열이 메모리에 방치되어, 브라우저 프로세스 메모리 덤프나 취약점 발생 시 탈취될 수 있다.

### 1.2 Wasm 선형 메모리 샌드박스의 도입 이유
* WebAssembly(Wasm)는 GC가 없는 64KB 단위의 독립된 가상 메모리 공간(Linear Memory, `ArrayBuffer`)을 가진다.
* 이 선형 메모리 안에서만 암복호화를 수행하고, 연산 종료 직후 해당 메모리를 물리적으로 `0x00` 소거(Volatile Zeroize)한 뒤 해제하여 평문 잔류 시간을 최소화한다.
* 본 문서는 `crates/crypto-core/src/lib.rs`에 구현된 C-ABI 인터페이스를 C 언어의 기계적 동작으로 1:1 치환하여 규명한다.

---

## 2. C 언어 vs Rust C-ABI 1:1 기계적 코드 대조

Rust 문법의 껍데기를 벗겨내면, 내부에서 일어나는 모든 연산은 C 언어의 포인터 및 힙 메모리 제어와 100% 동일하다.

### 2.1 메모리 할당: `prf_vault_alloc`

* **C 언어 구현**:
  ```c
  uint8_t* prf_vault_alloc(size_t size) {
      if (size == 0) return NULL;
      // 0으로 초기화된 힙 메모리 할당
      uint8_t* ptr = (uint8_t*)calloc(size, 1);
      return ptr;
  }
  ```

* **Rust C-ABI 구현 (`crates/crypto-core/src/lib.rs`)**:
  ```rust
  #[unsafe(no_mangle)]
  pub unsafe extern "C" fn prf_vault_alloc(size: usize) -> *mut u8 {
      if size == 0 {
          return std::ptr::null_mut(); // return NULL;
      }
      let mut buffer = vec![0u8; size].into_boxed_slice(); // calloc(size, 1)
      let ptr = buffer.as_mut_ptr();                       // 힙 버퍼의 시작 주소
      std::mem::forget(buffer); // 핵심: 컴파일러 자동 drop() 방지 (C의 malloc 유지 상태)
      ptr                       // return ptr;
  }
  ```

* **저수준 동작 원리**:
  * Rust 컴파일러는 기본적으로 스코프를 벗어나는 객체를 자동 해제(`drop`)한다.
  * 외부 JavaScript가 해당 주소를 받아 쓸 수 있도록 `std::mem::forget`을 호출하여 Rust의 자동 해제 추적을 강제 차단하고 C의 `malloc` 상태로 힙에 남겨둔다.

---

### 2.2 물리 소거 및 해제: `prf_vault_dealloc_zeroize`

* **C 언어 구현**:
  ```c
  void prf_vault_dealloc_zeroize(uint8_t* ptr, size_t size) {
      if (ptr == NULL || size == 0) return;
      
      // 컴파일러 Dead Code Elimination(DCE)을 차단하는 volatile 소거 (C23: memset_explicit)
      volatile uint8_t* vptr = (volatile uint8_t*)ptr;
      for (size_t i = 0; i < size; i++) {
          vptr[i] = 0x00;
      }
      
      free(ptr); // 힙 반환
  }
  ```

* **Rust C-ABI 구현 (`crates/crypto-core/src/lib.rs`)**:
  ```rust
  #[unsafe(no_mangle)]
  pub unsafe extern "C" fn prf_vault_dealloc_zeroize(ptr: *mut u8, size: usize) {
      if ptr.is_null() || size == 0 {
          return;
      }
      unsafe {
          let slice = std::slice::from_raw_parts_mut(ptr, size); // (uint8_t*)ptr 캐스팅
          slice.zeroize();                                    // volatile write (0x00 기록)
          let boxed = Box::from_raw(slice as *mut [u8]);      // 포인터 소유권 복원
          drop(boxed);                                        // free(ptr)
      }
  }
  ```

* **저수준 동작 원리**:
  * 단순한 `memset(ptr, 0, size)`은 "이후 해당 메모리를 읽는 코드가 없다"는 이유로 컴파일러 최적화(Dead Store Elimination) 단계에서 소거 명령이 완전히 삭제될 수 있다.
  * Rust의 `zeroize` 크레이트는 `core::sync::atomic` 및 `write_volatile`을 강제하여 CPU 레벨에서 메모리 쓰기가 생략되지 않고 반드시 집행되도록 보장한다.
  * `Box::from_raw`는 C의 `free(ptr)` 직전 단계처럼, 이전에 `forget`으로 분리했던 힙 청크의 소유권을 할당자(`dlmalloc`)에 재등록하여 메모리를 해제한다.

---

### 2.3 마스터 키 도출: `prf_vault_derive_master_key`

* **C 언어 구현**:
  ```c
  int prf_vault_derive_master_key(const uint8_t* prf_output, const uint8_t* salt, uint8_t* out_key) {
      if (!prf_output || !salt || !out_key) return -1;
      
      uint8_t okm[32] = {0};
      // HKDF-Extract & Expand (RFC 5869)
      int res = HKDF_Extract_and_Expand(
          prf_output, 32,
          salt, 32,
          (const uint8_t*)"PrfVault/v1/MasterEncryptionKey", 30,
          okm, 32
      );
      if (res != 0) return -5;
      
      memcpy(out_key, okm, 32);     // 결과를 출력 포인터로 복사
      explicit_bzero(okm, 32);       // 스택 임시 키 물리 소거
      return 0;
  }
  ```

* **Rust C-ABI 구현 (`crates/crypto-core/src/lib.rs`)**:
  ```rust
  #[unsafe(no_mangle)]
  pub unsafe extern "C" fn prf_vault_derive_master_key(
      prf_output_ptr: *const u8,
      salt_ptr: *const u8,
      out_key_ptr: *mut u8,
  ) -> i32 {
      if prf_output_ptr.is_null() || salt_ptr.is_null() || out_key_ptr.is_null() {
          return ERR_NULL_POINTER;
      }

      let (prf_output, salt) = (
          std::slice::from_raw_parts(prf_output_ptr, 32),
          std::slice::from_raw_parts(salt_ptr, 32),
      );

      let hk = Hkdf::<Sha256>::new(Some(salt), prf_output);
      let mut okm = [0u8; 32];
      if hk.expand(HKDF_INFO, &mut okm).is_err() {
          return ERR_HKDF_FAILED;
      }

      std::ptr::copy_nonoverlapping(okm.as_ptr(), out_key_ptr, 32); // memcpy
      okm.zeroize();                                                 // explicit_bzero
      SUCCESS
  }
  ```

---

### 2.4 동적 버퍼 반환 (이중 포인터): `prf_vault_encrypt` / `decrypt`

* **C 언어 관점**:
  암호화된 결과물의 크기를 사전에 알 수 없으므로, C에서 흔히 쓰는 **이중 포인터(`uint8_t** out_ptr`)** 패턴을 사용해 함수 내부에서 새로 할당된 버퍼 주소를 호출자에게 반환한다.
  ```c
  *out_blob_ptr = allocated_buffer_ptr; // 새로 할당된 Wasm 힙 주소 전달
  *out_blob_len = total_length;         // 할당된 바이트 길이 전달
  ```

* **Rust C-ABI 구현**:
  ```rust
  let mut boxed = blob.into_boxed_slice();
  unsafe {
      *out_blob_len = boxed.len();
      *out_blob_ptr = boxed.as_mut_ptr();
  }
  std::mem::forget(boxed); // 반환된 버퍼가 즉시 free되지 않도록 소유권 차단
  ```

---

## 3. WebAssembly 가상 머신과 네이티브 하드웨어 아키텍처 차이

### 3.1 스택 머신 vs 물리 레지스터 머신
* **x86-64 / ARM (물리 레지스터 머신)**:
  * 명령어가 명시적 하드웨어 레지스터(RAX, R1, X0 등)를 참조한다.
  * 컴파일러는 물리 레지스터 개수 한계 안에서 변수를 배치하기 위해 복잡한 레지스터 할당(Graph Coloring)을 수행한다.
* **WebAssembly (스택 기반 중간 언어, IR)**:
  * 연산 명령어에 레지스터 이름이 없다 (`i32.add`, `i64.load`).
  * 피연산자는 무조건 평가 스택의 최상단(TOS)에서 POP되고 결과는 다시 스택으로 PUSH된다.
  * 이로 인해 명령어 바이트코드 크기가 극도로 축소되며, 타깃 CPU의 아키텍처(x86, ARM, RISC-V)에 구애받지 않고 브라우저 JIT 컴파일러(V8 TurboFan)가 현장에서 최적 물리 기계어로 컴파일한다.

### 3.2 제어 흐름 무결성 (Safe Invisible Call Stack)
* **네이티브 C 환경의 취약점**:
  * 단일 가상 메모리 주소 공간 안에 Stack(복귀 주소 RIP, 지역변수)과 Heap이 공존한다.
  * 버퍼 오버플로우 발생 시 Return Address를 덮어써서 악성 쉘코드를 실행(ROP 공격)할 수 있다.
* **Wasm 환경의 보안 격리**:
  * Wasm의 함수 호출 복귀 주소와 콜 스택은 **Wasm 바이트코드나 메모리 포인터로 절대 접근할 수 없는 브라우저 V8 내부 격리 영역(Invisible Stack)**에 존재한다.
  * Wasm 내부의 `memory`는 브라우저가 할당해 준 순수한 1차원 바이트 배열(`ArrayBuffer`)일 뿐이다.
  * 따라서 Wasm 내부에서 버퍼 오버플로우가 발생하더라도 힙 데이터가 깨질 뿐, **CPU의 Instruction Pointer를 탈취당하는 RCE(원격 코드 실행) 공격은 하드웨어/가상머신 구조적으로 불가능**하다.

---

## 4. 기술 면접 대비 핵심 문답 (Technical Interview Defense)

* **Q. 왜 TypeScript Web Crypto API 대신 굳이 Rust Wasm을 사용했는가?**
  * **A**: "Web Crypto API는 암호화 연산 자체는 빠르지만, JS 런타임의 가비지 컬렉터 특성상 마스터 키와 비밀번호 평문이 메모리에 방치되는 시간을 통제할 수 없습니다. 메모리 덤프 공격에 대비해 Wasm 선형 메모리 안에서만 암복호화를 수행하고, 작업 직후 `volatile zeroize`로 0x00 물리 소거를 강제하기 위해 Wasm C-ABI 샌드박스를 구축했습니다."

* **Q. Rust 코드를 작성할 때 소유권(Ownership) 시스템을 왜 `mem::forget`으로 우회했는가?**
  * **A**: "Wasm C-ABI 인터페이스를 통해 JavaScript 런타임으로 메모리 주소(포인터)를 넘겨주어야 하기 때문입니다. Rust의 기본 RAII 소유권 정책을 그대로 두면 함수 종료 시점에 버퍼가 자동 해제되므로, `std::mem::forget`을 사용해 C의 `malloc`처럼 메모리를 유지시킨 뒤, JS 작업이 끝난 후 `prf_vault_dealloc_zeroize`를 통해 명시적으로 소유권을 복원하여 소거 및 해제(`free`)했습니다."
