## FW-Update
안전한 펌웨어 업데이트 로직 구현하기 😉

#### Generate FW
- [x] FW 생성
- [x] FW Hash 계산
- [x] FW를 Symmetric Key로 암호화
  - FW에 정의된 Metadata 활용하여 boot/* 암호화
  - FW에 정의된 Metadata 활용하여 opt/* 암호화
- [ ] FW Hash를 제조사의 Private Key로 암호화 (미완)
- [ ] Symmetric Key를 사용자의 Public Key로 암호화 (미완)
- [x] 암호화된 FW Hash & 암호화된 FW & 암호화된 Symmetric Key → tar로 묶기

#### Obfuscation
- [x] LLVM Compiler를 이용한 Updater Obfuscation

#### Updater
- [x] tar 해제
- [ ] 암호화된 FW Hash를 제조사의 Public Key로 복호화 (미완)
- [ ] 암호화된 Symmetric Key를 사용자의 Private Key로 복호화 (미완)
- [x] 암호화된 FW를 복호화된 Symmetric Key로 복호화
  - FW에 정의된 Metadata 활용하여 boot/* 복호화
  - FW에 정의된 Metadata 활용하여 opt/* 복호화
- [x] 복호화된 FW의 Hash 계산
- [x] 계산된 FW Hash와 생성 단계의 FW Hash 값을 비교
  - 동일하다면: 업데이트 성공 😉
  - 동일하지 않다면: 업데이트 실패 👿

### 요구 사항
1. Firmware 파일들은 Updater에 의해 /var/update_test/ 디렉토리 하위에 추출된다.

2. 다음 파일들은 암호화 및 서명을 통해 기밀성과 무결성을 제공해야 한다.
    - 암호화 수행 시 openssl의 evp 사용
    - ./boot/ 디렉토리 내 모든 파일
    - ./opt/ 디렉토리 내 모든 파일
    - boot/* opt/* 디렉토리는 개별 파일을 암호화

3. 다음 파일은 암호화 수행을 진행하지 않는다.
    - ./documentation.tar 파일
    - /var/update_test/ 디렉토리에 untar

### 보안성의 한계
- Key를 안전하게 저장할 수 있는 RoT(Root of Trust)가 부재하다.
- HSM, Secure Element 등 안전하게 키를 관리할 수 있는 별도의 모듈이 필요하다.
- ARM TrustZone에서 Secure State에 키를 저장하는 것도 발전시킬 수 있는 방법이다.

### 추가로 구현한 사항
- FW에 대한 암호화는 encrypt가 수행하여, encrypted 디렉토리에 저장한다.
- FW에 대한 암호화를 수행했던 Updater를 복호화를 수행하도록 변경했다.
- 하드코드 되어있던 Key, Input Vector를 key.txt, iv.txt 파일을 읽어오는 것으로 변경했다. 
- Malicious FW를 탐지하기 위해 HASH(SHA-256) 알고리즘을 이용했다.
- Origin FW의 Hash값은 Manufacture 단계에서 계산되었다고 가정하였고, 이를 hash.txt에 보관하였다.
- Updater를 실행하면 추출하려는 FW의 Hash를 새로 계산하고, 이를 Origin FW의 Hash와 비교한다.
- 새로 계산된 Hash 값과 Origin Hash 값이 다르다면, Updater에서 에러 메시지를 출력하고 프로그램은 종료된다.
- LLVM Compiler를 이용해 Updater Binary를 난독화했다.
- LLVM Backend Architecture를 ARM으로 설정하여 Intel CPU에서 작동하지 않는다.
- ARM으로 설정한 이유는 실제 엔드포인트 디바이스들의 CPU가 ARM 계열이기 때문이다.

### Prerequisite: Encryption
```sh
$ sudo apt-get install pv
$ sudo apt-get install libssl-dev
```

### Prerequiesite: Obfuscation
```sh
$ sudo apt install linuxbrew-wrapper
$ brew install cmake
$ mkdir ./src/build
$ cd ./src/build
$ sudo apt install cmake
$ cmake -DLLVM_ENABLE_PROJECTS=clang -G "Unix Makefiles" ../llvm  -DLLVM_ENABLE_PROJECTS="clang;clang-tools-extra" -DLLVM_USE_LINKER=gold -DCMAKE_BUILD_TYPE=Release
$ make -j8
```

### Make FW Hash
```sh
$ gcc hash.c -o hash -lssl -lcrypto
$ ./hash
```

### Make Encrypted Firmware
```sh
$ gcc encrypt.c -o encrypt -lssl -lcrypto
$ ./encrypt ./FW
$ tar -cvf boot.tar ./encrypted/boot
$ tar -cvf documentation.tar ./encrypted/documentation
$ tar -cvf opt.tar ./encrypted/opt
$ python3 makeFW.py
```

### Make Updater: Firmware Obfuscation using LLVM
> ![LLVM](https://user-images.githubusercontent.com/20378368/128179060-569c2c34-ee66-48f9-ad23-a98a80c9fa18.png)
```sh
$ ./src/build/bin/clang -emit-llvm -c -S Updater.c -o Updater.ll
$ ./src/build/bin/opt -load ./src/build/lib/LLVMObfuscation.so -preprocess Updater.ll -o Updater.ll
$ ./src/build/bin/opt -load ./src/build/lib/LLVMObfuscation.so -rof Updater.ll -o Updater.ll
$ ./Updater ./enFW
```
