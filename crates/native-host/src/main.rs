mod protocol;
pub mod windows_hello;

use std::io::{self, BufReader, BufWriter};

fn main() -> io::Result<()> {
    // Windows 파이프라인에서 버퍼링 최적화 및 4바이트 uint32 LE 프레임 안정성 확보
    let stdin = io::stdin();
    let stdout = io::stdout();

    let mut reader = BufReader::new(stdin.lock());
    let mut writer = BufWriter::new(stdout.lock());

    while let Ok(Some(raw_bytes)) = protocol::read_message(&mut reader) {
        let (response, should_exit) = protocol::handle_message(&raw_bytes);

        if let Err(e) = protocol::write_message(&mut writer, &response) {
            eprintln!("[NativeHost] 응답 전송 실패: {e}");
            break;
        }

        // 유효하지 않은 페이로드 수신 시 Fail-safe 정책에 따라 세션을 즉각 종료
        if should_exit {
            eprintln!("[NativeHost] Fail-safe 트리거: 비정상 페이로드로 인해 호스트 프로세스 종료");
            break;
        }
    }

    Ok(())
}
