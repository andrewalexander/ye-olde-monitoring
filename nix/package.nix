{ lib, buildGo127Module }:

# go.mod needs 1.27; nixpkgs' default go may lag behind.
buildGo127Module {
  pname = "dnscount";
  version = "0.1.0";

  src = lib.cleanSourceWith {
    src = ./..;
    # Keep rebuilds to Go changes: skip build output, databases and deploy docs.
    filter = path: type:
      let name = baseNameOf path; in
      !(builtins.elem name [ "dist" "raw" "result" "deploy" "docs" "nix" ".git" ".gitignore" ])
      && !(lib.hasSuffix ".db" name)
      && !(lib.hasInfix ".db-" name);
  };

  vendorHash = "sha256-sJn4yiUb227dGjpFF6dw/oXOLQ/2mdSikqymhkDchSM=";

  subPackages = [ "cmd/dnscount" ];
  env.CGO_ENABLED = 0; # modernc.org/sqlite is pure Go
  ldflags = [ "-s" "-w" ];

  meta = {
    description = "Hit counter and request/DNS logger backed by one SQLite file";
    mainProgram = "dnscount";
    platforms = lib.platforms.unix;
  };
}
