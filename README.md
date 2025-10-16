# **Pintos Project 3 — Virtual Memory**

**Pintos**는 교육용 운영체제 커널입니다. 리눅스처럼 거대한 코드베이스를 한 번에 이해하기 어렵다는 문제를 해결하기 위해, **작고 읽기 쉬우며 실험 가능한** 커널 골격을 제공합니다. 학생은 여기에 **스레드, 프로세스, 파일 시스템, 가상 메모리** 같은 핵심 기능을 직접 붙여 넣으며, 단순한 라이브러리 코딩이 아닌 **시스템 수준의 설계·디버깅 경험**을 얻게 됩니다.

Project 3의 주제인 **가상 메모리(Virtual Memory)** 는 현대 OS가 프로세스들을 **서로 격리**하고, **메모리를 효율적으로 사용**하며, **큰 프로그램도 적은 물리 메모리에서 실행**되게 하는 핵심 기술입니다. 이 과제를 통해 “페이지 폴트가 왜 생기고, OS가 그 순간 무슨 일을 하는가?”를 실제 커널 코드로 체감하게 됩니다.


## **프로젝트: 3 (가상 메모리)**

- **무엇을 만드나?**
    
    페이지 단위로 메모리를 관리하는 **가상 메모리 서브시스템**을 확장합니다. 필요할 때만 페이지를 채우는 **지연 로딩(lazy/demand paging)**, 물리 메모리가 모자라면 디스크로 내보내는 **스왑(swap)**, 파일 내용을 메모리에 투명하게 매핑하는 **mmap/munmap** 등을 구현합니다.
    
- **왜 배우나?**
    - **격리와 안정성**: 잘못된 접근을 잡아내고 프로세스를 종료하는 **페이지 폴트 처리**를 익힙니다.
    - **효율성**: 실제로 접근한 데이터만 로딩하는 **지연 로딩**으로 입출력과 메모리 낭비를 줄입니다.
    - **자원 관리**: **프레임 테이블 + 교체 정책**으로 물리 메모리를 공정하게 배분합니다.
    - **영속성과 일관성**: 파일-백드 페이지의 **쓰기 반영(write-back)** 과 **동기화**를 다룹니다.
    - **경합/락 설계**: 여러 실행 흐름이 동일 자원을 안전하게 공유하도록 **동기화**를 설계합니다.


## **구현 기능 요약 (설계 포인트)**

### **1) 보조 페이지 테이블(Supplemental Page Table; SPT)**

- **하는 일**: “이 가상 주소의 페이지는 어떤 타입이고, 어디서 어떻게 채워야 하는가?”를 기록하는 **프로세스 전용 메타데이터** 사전입니다.
- **왜 필요?**: 하드웨어 페이지 테이블은 “매핑됨/안 됨”만 알기 쉬운데, **어떻게 로드할지**(파일에서? 스왑에서? 0으로?)는 OS가 기억해야 함.
- **설계 포인트**
    - 해시/트리 등으로 **빠른 조회**(평균 O(1))
    - 키: 페이지 **기준 주소(페이지 정렬된 VA)**
    - 값: **페이지 타입(익명/파일-백드)**, 소스(파일+오프셋/스왑 슬롯), 권한 등

### **2) 지연 로딩(Lazy Loading) & 수요 페이징(Demand Paging)**

- **하는 일**: 실행 시 파일 전체를 읽지 않고, **접근하는 순간**(페이지 폴트 시) 필요한 페이지만 로드합니다.
- **설계 포인트**
    - SPT에 “어떻게 채울지”만 미리 적어 놓고, **첫 접근 때 vm_claim_page()** 로 실제 할당/적재
    - 파일-백드: 파일에서 읽어 채움, 익명: 0으로 초기화

### **3) 프레임 테이블(Frame Table) & 교체 정책(Eviction)**

- **하는 일**: “RAM에 어떤 페이지가 어느 프레임에 들어있는지”를 추적하고, RAM이 가득 차면 **누구를 내보낼지** 결정합니다.
- **교체 정책**: 예) **Clock/Second-chance** — 최근에 안 쓰인 페이지부터 희생
- **설계 포인트**
    - 프레임 <-> SPT 엔트리 간 **양방향 연결**(역참조)
    - I/O 중인 프레임은 **핀(pin)** 으로 잠깐 희생 금지
    - 락 순서/보유 기간을 짧게 유지해 **교착 방지**

### **4) 스왑(Swap) — 익명 페이지 내보내기/가져오기**

- **하는 일**: 익명 페이지(스택/힙 등)를 디스크 **스왑 영역**에 저장했다가 필요하면 다시 불러옵니다.
- **설계 포인트**
    - “한 페이지 = 고정된 섹터 수” 단위로 **슬롯 관리**(할당/해제 비트맵 등)
    - 스왑아웃: 프레임 → 디스크, SPT에 “이 페이지는 스왑 슬롯 #n”으로 갱신
    - 스왑인: 다시 RAM으로 가져오고 슬롯 해제

### **5) 파일-백드 페이지 & 메모리 매핑(mmap/munmap)**

- **하는 일**: 파일의 일부를 메모리에 매핑하여 **파일 I/O를 메모리 접근처럼** 사용할 수 있게 합니다.
- **지연 로딩**과 결합되어, 접근 시 해당 부분만 파일에서 읽어 옵니다.
- **munmap**: 더티 페이지는 파일에 **write-back**, 클린 페이지는 해제
- **주소 선택 힌트**: addr == NULL 인 경우, **연속된 빈 가상 주소 구간**을 찾아 시작 주소를 정합니다(페이지 정렬/유저 영역/겹침 금지 검사).

### **6) 스택 자동 성장(Stack Growth)**

- **하는 일**: 프로그램이 스택을 조금씩 더 쓰면, OS가 **허용 범위 내에서** 새 페이지를 만들어 스택을 확장합니다.
- **설계 포인트**
    - “폴트 주소가 현재 스택 포인터 근처인가?” 등 **합법 조건** 판정
    - 성공 시 익명 페이지를 **claim** 해서 0-초기화

### **7) 페이지 폴트 처리기(Page Fault Handler)**

- **하는 일**: 접근 예외가 나면 원인을 분석(존재X/권한X/커널 접근 등)하고, **정상적인 경우에는 필요한 페이지를 즉시 준비**합니다.
- **일반 흐름**
    1. SPT 조회 → 있으면 타입별 로드(파일/스왑/0-fill)
    2. 없으면 **스택 성장 조건**인지 확인 후 확장
    3. 진짜 오류(권한 위반 등)면 프로세스 종료

### **8) 동기화 & 오류 처리**

- **하는 일**: 파일 시스템 락, 프레임 락, SPT 락 등 **여러 락의 순서**를 안정적으로 맞춰 교착을 방지합니다.
- **설계 포인트**
    - **락 획득/해제의 일관성**
    - 인터럽트 컨텍스트에서 금지해야 할 작업 회피
    - 실패 시 **자원 정리**(파일 핸들/슬롯/프레임) 확실히


## **디렉터리 개요**

- pintos/vm/ : VM 핵심 코드(페이지 타입, 프레임/스왑/클레임 로직 등)
- pintos/userprog/ : 시스템콜, 프로세스 로딩/페이지 폴트 진입부
- pintos/threads/ : 스케줄러·락·페이지 할당자 등 커널 공통
- pintos/tests/ : 채점 및 개별 테스트 프로그램(과제 배포본 기준)


## 테스트 결과

 <img src="Pintos_VM_result.PNG" width="400px">


```bash
=== Test Summary ===
Passed: 140
  - args-none
  - args-single
  - args-multiple
  - args-many
  - args-dbl-space
  - halt
  - exit
  - create-normal
  - create-empty
  - create-null
  - create-bad-ptr
  - create-long
  - create-exists
  - create-bound
  - open-normal
  - open-missing
  - open-boundary
  - open-empty
  - open-null
  - open-bad-ptr
  - open-twice
  - close-normal
  - close-twice
  - close-bad-fd
  - read-normal
  - read-bad-ptr
  - read-boundary
  - read-zero
  - read-stdout
  - read-bad-fd
  - write-normal
  - write-bad-ptr
  - write-boundary
  - write-zero
  - write-stdin
  - write-bad-fd
  - fork-once
  - fork-multiple
  - fork-recursive
  - fork-read
  - fork-close
  - fork-boundary
  - exec-once
  - exec-arg
  - exec-boundary
  - exec-missing
  - exec-bad-ptr
  - exec-read
  - wait-simple
  - wait-twice
  - wait-killed
  - wait-bad-pid
  - multi-recurse
  - multi-child-fd
  - rox-simple
  - rox-child
  - rox-multichild
  - bad-read
  - bad-write
  - bad-read2
  - bad-write2
  - bad-jump
  - bad-jump2
  - pt-grow-stack
  - pt-grow-bad
  - pt-big-stk-obj
  - pt-bad-addr
  - pt-bad-read
  - pt-write-code
  - pt-write-code2
  - pt-grow-stk-sc
  - page-linear
  - page-parallel
  - page-merge-seq
  - page-merge-par
  - page-merge-stk
  - page-merge-mm
  - page-shuffle
  - mmap-read
  - mmap-close
  - mmap-unmap
  - mmap-overlap
  - mmap-twice
  - mmap-write
  - mmap-ro
  - mmap-exit
  - mmap-shuffle
  - mmap-bad-fd
  - mmap-clean
  - mmap-inherit
  - mmap-misalign
  - mmap-null
  - mmap-over-code
  - mmap-over-data
  - mmap-over-stk
  - mmap-remove
  - mmap-zero
  - mmap-bad-fd2
  - mmap-bad-fd3
  - mmap-zero-len
  - mmap-off
  - mmap-bad-off
  - mmap-kernel
  - lazy-file
  - lazy-anon
  - swap-file
  - swap-anon
  - swap-iter
  - swap-fork
  - lg-create
  - lg-full
  - lg-random
  - lg-seq-block
  - lg-seq-random
  - sm-create
  - sm-full
  - sm-random
  - sm-seq-block
  - sm-seq-random
  - syn-read
  - syn-remove
  - syn-write
  - alarm-single
  - alarm-multiple
  - alarm-simultaneous
  - alarm-priority
  - alarm-zero
  - alarm-negative
  - priority-change
  - priority-donate-one
  - priority-donate-multiple
  - priority-donate-multiple2
  - priority-donate-nest
  - priority-donate-sema
  - priority-donate-lower
  - priority-fifo
  - priority-preempt
  - priority-sema
  - priority-condvar
  - priority-donate-chain
Failed: 0
```

## **참고 자료**

- KAIST Pintos Project 3 공식 문서
    
    https://casys-kaist.github.io/pintos-kaist/project3/introduction.html