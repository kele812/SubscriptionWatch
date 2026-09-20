// Applies the overlay only to the reviewed upstream revision. No fuzzy patches.
import { readFileSync, writeFileSync, cpSync, existsSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
const root = process.argv[2];
if (!root) throw Error("usage: node apply.mjs UPSTREAM_DIRECTORY");
const replacements = [];
function replace(file, old, next) {
  const p = path.join(root, file);
  let s = replacements.find((x) => x.p === p)?.s ?? readFileSync(p, "utf8");
  if (s.split(old).length !== 2)
    throw Error("Upstream changed: " + file + " / " + old.slice(0, 60));
  s = s.replace(old, next);
  const i = replacements.findIndex((x) => x.p === p);
  if (i < 0) replacements.push({ p, s });
  else replacements[i] = { p, s };
}
const config = "internal/config/config.go",
  service = "internal/service/service.go";
replace(
  config,
  "type Config struct {",
  'type Config struct {\n\tWatchAccess watchaccess.Config `yaml:"watch_access"`',
);
replace(
  config,
  '"github.com/cedar2025/xboard-node/internal/nlog"',
  '"github.com/cedar2025/xboard-node/internal/nlog"\n"github.com/cedar2025/xboard-node/internal/watchaccess"',
);
replace(
  config,
  "type KernelConfig struct {",
  'type KernelConfig struct {\n\tWatchRecord func(int,string,string,string) `yaml:"-" json:"-"`',
);
replace(
  service,
  '"github.com/cedar2025/xboard-node/internal/cert"',
  '"github.com/cedar2025/xboard-node/internal/cert"\n"github.com/cedar2025/xboard-node/internal/watchaccess"',
);
replace(
  service,
  "type Service struct {",
  "type Service struct {\n\twatchAccess *watchaccess.Reporter\n\twatchErr error",
);
replace(
  service,
  "\tk := newKernel(cfg.Kernel, initialKernelType)",
  "\t// Copy configuration: multi-node services must not share callbacks.\n\tcopyCfg := *cfg\n\tcfg = &copyCfg\n\twatch, watchErr := watchaccess.New(cfg.WatchAccess)\n\tif watch != nil { cfg.Kernel.WatchRecord = watch.Record }\n\tk := newKernel(cfg.Kernel, initialKernelType)",
);
replace(
  service,
  "svc := &Service{",
  "svc := &Service{\nwatchAccess: watch, watchErr: watchErr,",
);
replace(
  service,
  "func (s *Service) Run(ctx context.Context) error {",
  `func (s *Service) Run(ctx context.Context) error {
  if s.watchErr != nil { return s.watchErr }
  if s.watchAccess != nil {
    watchCtx, stopWatch := context.WithCancel(ctx)
    done := make(chan struct{})
    go func(){defer close(done);s.watchAccess.Run(watchCtx)}()
    defer func(){stopWatch();<-done}()
  }`,
);
const tracker = "internal/kernel/singbox/conntracker.go";
replace(
  tracker,
  "type ConnTracker struct {",
  "type ConnTracker struct {\nwatchRecord func(int,string,string,string)",
);
replace(
  tracker,
  "func (t *ConnTracker) recordAccess(userID int, sourceIP, network, destination string) *accesslog.Activity {",
  `func (t *ConnTracker) recordAccess(userID int, sourceIP, network, destination string) *accesslog.Activity {
 if t.watchRecord != nil { t.watchRecord(userID,sourceIP,network,destination);return nil }`,
);
replace(
  "internal/kernel/singbox/singbox.go",
  "s.connTracker = NewConnTracker(0)",
  "s.connTracker = NewConnTracker(0)\n s.connTracker.watchRecord = s.cfg.WatchRecord",
);
const dispatcher = "internal/kernel/xray/dispatcher.go";
replace(
  dispatcher,
  "type LimitDispatcher struct {",
  "type LimitDispatcher struct {\nwatchRecord func(int,string,string,string)",
);
replace(
  dispatcher,
  "\tseq := d.accessSeq.Add(1)",
  "\tif d.watchRecord != nil { d.watchRecord(uid,sourceIP,dest.Network.SystemString(),dest.String());return nil }\n\tseq := d.accessSeq.Add(1)",
);
replace(
  "internal/kernel/xray/xray.go",
  "\tld := globalLimitDispatcher.Load()",
  "\tld := globalLimitDispatcher.Load()\n\tif ld != nil { ld.watchRecord = x.cfg.WatchRecord }",
);
// All replacements have been validated before any source is changed.
for (const { p, s } of replacements) writeFileSync(p, s);
cpSync(
  path.join(path.dirname(fileURLToPath(import.meta.url)), "overlay"),
  root,
  { recursive: true },
);
console.log("SubscriptionWatch 3.8.0 node overlay applied");
