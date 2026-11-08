{
  lib,
  rustPlatform
}:

rustPlatform.buildRustPackage {
  pname = "linaudit";
  version = "git";
  src = ../.;

  cargoLock = {
    lockFile = ../Cargo.lock;
  };

  checkFlags = [
    "--skip=barrido_completo"
    "--skip=snapshots_fuera_del_barrido"
  ];

  meta = with lib; {
    description = "Audit tool for Linux Systems";
    license = licenses.agpl3Plus;
    mainProgram = "linaudit";
  };
}
