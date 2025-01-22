const APPGUARD_PROTOBUF_PATH: &str = "./proto/appguard.proto";
const AIGUARD_PROTOBUF_PATH: &str = "./proto/aiguard.proto";
const PROTOBUF_DIR_PATH: &str = "./proto";

fn main() {
    tonic_build::configure()
        .out_dir("./src/proto")
        .compile_protos(
            &[APPGUARD_PROTOBUF_PATH, AIGUARD_PROTOBUF_PATH],
            &[PROTOBUF_DIR_PATH],
        )
        .expect("Protobuf files generation failed");
}
