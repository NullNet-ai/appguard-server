const APPGUARD_PROTOBUF_PATH: &str = "./proto/appguard.proto";
// const AIGUARD_PROTOBUF_PATH: &str = "./proto/aiguard.proto";
const PROTOBUF_DIR_PATH: &str = "./proto";

fn main() {
    for out_dir in ["./src/proto", "./libappguard/src/proto"] {
        tonic_build::configure()
            .out_dir(out_dir)
            .compile_protos(&[APPGUARD_PROTOBUF_PATH], &[PROTOBUF_DIR_PATH])
            .expect("Protobuf files generation failed");
    }
}
