// 필요한 헤더 파일들을 포함합니다.
#include <windows.h>      // Windows API 함수를 사용하기 위한 필수 헤더 (예: OpenProcess, WriteProcessMemory)
#include <tlhelp32.h>     // 프로세스와 모듈 정보를 얻기 위한 툴헬프 함수 (예: CreateToolhelp32Snapshot)
#include <vector>         // 동적 배열인 std::vector를 사용하기 위함 (오프셋 체인 저장)
#include <iostream>       // 콘솔 입출력을 위한 헤더 (예: std::cout, std::cerr)
#include <thread>         // 멀티스레딩을 사용하기 위함 (메인 로직과 트레이너 루프를 분리)

/**
 * @brief 주어진 프로세스 이름으로 프로세스 ID (PID)를 찾습니다.
 * @param procName 찾고자 하는 프로세스의 실행 파일 이름 (예: L"ac_client.exe")
 * @return 성공 시 프로세스 ID (DWORD), 실패 시 0을 반환합니다.
 */
DWORD GetProcId(const wchar_t* procName) {
    DWORD procId = 0;
    // 시스템의 모든 프로세스 스냅샷을 생성합니다.
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 procEntry;
        procEntry.dwSize = sizeof(procEntry); // 구조체 크기 초기화

        // 첫 번째 프로세스 정보를 가져옵니다.
        if (Process32First(hSnap, &procEntry)) {
            do {
                // 프로세스 이름을 비교합니다. (_wcsicmp는 대소문자를 무시하고 비교)
                if (!_wcsicmp(procEntry.szExeFile, procName)) {
                    procId = procEntry.th32ProcessID; // 일치하는 프로세스를 찾으면 ID 저장
                    break; // 루프 종료
                }
            } while (Process32Next(hSnap, &procEntry)); // 다음 프로세스 정보를 가져옵니다。
        }
    }
    CloseHandle(hSnap); // 스냅샷 핸들을 닫아 리소스를 해제합니다.
    return procId;
}

/**
 * @brief 특정 프로세스 내에서 로드된 모듈의 베이스 주소를 찾습니다.
 * @param procId 모듈을 찾을 대상 프로세스의 ID
 * @param modName 찾고자 하는 모듈의 이름 (예: L"ac_client.exe")
 * @return 성공 시 모듈의 베이스 주소 (uintptr_t), 실패 시 0을 반환합니다.
 */
uintptr_t GetModuleBaseAddress(DWORD procId, const wchar_t* modName) {
    uintptr_t baseAddr = 0;
    // 특정 프로세스에 로드된 모듈들의 스냅샷을 생성합니다.
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, procId);
    if (hSnap != INVALID_HANDLE_VALUE) {
        MODULEENTRY32 modEntry;
        modEntry.dwSize = sizeof(modEntry); // 구조체 크기 초기화

        // 첫 번째 모듈 정보를 가져옵니다.
        if (Module32First(hSnap, &modEntry)) {
            do {
                // 모듈 이름을 비교합니다.
                if (!_wcsicmp(modEntry.szModule, modName)) {
                    baseAddr = (uintptr_t)modEntry.modBaseAddr; // 모듈의 시작 주소(베이스 주소)를 저장
                    break; // 루프 종료
                }
            } while (Module32Next(hSnap, &modEntry)); // 다음 모듈 정보를 가져옵니다。
        }
    }
    CloseHandle(hSnap); // 스냅샷 핸들을 닫아 리소스를 해제합니다。
    return baseAddr;
}

/**
 * @brief 다단계 포인터 체인을 따라 최종 메모리 주소를 계산합니다. (DMA: Dynamic Memory Address)
 * @param hProc 대상 프로세스의 핸들
 * @param ptr 체인의 시작점이 되는 기본 포인터 주소
 * @param offsets 최종 주소에 도달하기 위해 더해줄 오프셋들의 배열
 * @return 계산된 최종 메모리 주소, 실패 시 0을 반환합니다.
 */
uintptr_t FindDMAAddy(HANDLE hProc, uintptr_t ptr, const std::vector<unsigned int>& offsets) {
    uintptr_t addr = ptr;
    for (size_t i = 0; i < offsets.size(); ++i) {
        std::cout << "[DEBUG] 단계 " << i << " 읽기 전 주소: 0x" << std::hex << addr << std::endl;
        
        // 현재 주소(addr)에 저장된 값을 읽어와 다시 addr에 저장합니다. 이 값이 다음 단계의 주소가 됩니다.
        // ReadProcessMemory: 다른 프로세스의 메모리를 읽는 함수
        if (!ReadProcessMemory(hProc, (BYTE*)addr, &addr, sizeof(addr), nullptr)) {
            std::cerr << "[ERROR] 메모리 읽기 실패! 단계 " << i << ", 주소: 0x" << std::hex << addr << std::endl;
            return 0; // 메모리 읽기 실패 시 0 반환
        }
        addr += offsets[i]; // 읽어온 주소에 현재 단계의 오프셋을 더합니다.
        std::cout << "[DEBUG] 단계 " << i << " 읽은 후 주소 + 오프셋: 0x" << std::hex << addr << std::endl;
    }
    return addr; // 모든 오프셋 계산이 끝나면 최종 주소를 반환합니다.
}

/**
 * @brief 트레이너의 핵심 로직을 무한 루프로 실행합니다.
 * @param hProc 대상 프로세스의 핸들
 * @param baseModule 대상 모듈의 베이스 주소
 */
void TrainerLoop(HANDLE hProc, uintptr_t baseModule) {
    // 각 값(HP, 탄약)의 포인터 체인 시작 주소입니다.
    // 이 주소는 (모듈 베이스 주소 + 정적 오프셋)으로 계산됩니다.
    const uintptr_t BASE_HP_PTR = baseModule + 0x00183828;   // HP 베이스 포인터
    const uintptr_t BASE_SMG_PTR = baseModule + 0x0017E0A8;  // SMG 베이스 포인터
    const uintptr_t BASE_AR_PTR = baseModule + 0x00183828;   // AR 베이스 포인터
    const uintptr_t BASE_SR_PTR = baseModule + 0x00183828;   // SR 베이스 포인터

    // 각 포인터 체인을 따라가기 위한 오프셋 배열입니다.
    const std::vector<unsigned int> offset_hp = { 0x8, 0x490, 0x64, 0x30, 0x30, 0x620 };   // HP 오프셋 체인
    const std::vector<unsigned int> offset_smg = { 0x138 };                                // SMG 오프셋 체인
    const std::vector<unsigned int> offset_ar = { 0x8, 0x76C, 0x9C4 };                     // AR 오프셋 체인
    const std::vector<unsigned int> offset_sr = { 0x8, 0x3DC, 0x56C };                     // SR 오프셋 체인

    int value = 999; // 메모리에 쓸 새로운 값

    while (true) { // 무한 루프 시작
        // FindDMAAddy 함수를 호출하여 HP와 각 탄약의 최종 메모리 주소를 계산합니다.
        uintptr_t hpAddr = FindDMAAddy(hProc, BASE_HP_PTR, offset_hp);
        uintptr_t smgAddr = FindDMAAddy(hProc, BASE_SMG_PTR, offset_smg);
        uintptr_t arAddr = FindDMAAddy(hProc, BASE_AR_PTR, offset_ar);
        uintptr_t srAddr = FindDMAAddy(hProc, BASE_SR_PTR, offset_sr);

        // WriteProcessMemory: 다른 프로세스의 메모리에 값을 쓰는 함수
        // HP 값 고정
        if (hpAddr != 0) {
            WriteProcessMemory(hProc, (LPVOID)hpAddr, &value, sizeof(value), nullptr);
        } else {
            std::cerr << "[ERROR] HP 주소 찾기 실패!" << std::endl;
        }

        // SMG 탄약 값 고정
        if (smgAddr != 0) {
            WriteProcessMemory(hProc, (LPVOID)smgAddr, &value, sizeof(value), nullptr);
        } else {
            std::cerr << "[ERROR] SMG 주소 찾기 실패!" << std::endl;
        }

        // AR 탄약 값 고정
        if (arAddr != 0) {
            WriteProcessMemory(hProc, (LPVOID)arAddr, &value, sizeof(value), nullptr);
        } else {
            std::cerr << "[ERROR] AR 주소 찾기 실패!" << std::endl;
        }

        // SR 탄약 값 고정
        if (srAddr != 0) {
            WriteProcessMemory(hProc, (LPVOID)srAddr, &value, sizeof(value), nullptr);
        } else {
            std::cerr << "[ERROR] SR 주소 찾기 실패!" << std::endl;
        }

        std::cout << "HP와 모든 탄약값을 999로 설정했습니다..." << std::endl;
        Sleep(2000); // 2초 동안 대기하여 CPU 사용률을 낮춥니다.
    }
}

int main() {
    const wchar_t* targetProcess = L"ac_client.exe"; // 목표 프로세스 이름
    DWORD procId = GetProcId(targetProcess); // 프로세스 ID 가져오기

    if (procId == 0) {
        std::cerr << "[ERROR] 프로세스를 찾을 수 없습니다." << std::endl;
        return 1; // 오류 코드 1로 종료
    }

    // 대상 프로세스의 핸들을 엽니다. 메모리 읽기/쓰기/작업 권한을 요청합니다.
    HANDLE hProc = OpenProcess(PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_VM_READ, FALSE, procId);
    if (!hProc) {
        std::cerr << "[ERROR] 프로세스를 열 수 없습니다. 에러 코드: " << GetLastError() << std::endl;
        return 1;
    }

    // 모듈의 베이스 주소를 가져옵니다.
    uintptr_t baseModule = GetModuleBaseAddress(procId, targetProcess);
    if (baseModule == 0) {
        std::cerr << "[ERROR] 모듈 베이스 주소를 찾을 수 없습니다." << std::endl;
        CloseHandle(hProc); // 핸들 닫기
        return 1;
    }

    // 트레이너 루프를 별도의 스레드에서 실행합니다.
    // 이렇게 하면 메인 스레드가 멈추지 않고 다른 작업을 할 수 있습니다.
    std::thread trainerThread(TrainerLoop, hProc, baseModule);
    trainerThread.detach(); // 메인 스레드와 독립적으로 실행되도록 분리합니다.

    std::cout << "트레이너가 활성화되었습니다. 프로그램을 종료하려면 아무 키나 누르세요." << std::endl;
    system("pause"); // 사용자가 키를 누를 때까지 대기

    CloseHandle(hProc); // 프로그램 종료 전 프로세스 핸들 닫기
    return 0;
}