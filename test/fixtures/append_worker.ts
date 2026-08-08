/* Child-process worker for the concurrency tests: appends `count` records to
   the chain at `path`, competing with sibling processes for the append lock. */
import { build, Recorder } from "../../src/record.ts";

const [, , path, countArg, label] = process.argv;
const count = Number(countArg);

const rec = new Recorder(path);
for (let i = 0; i < count; i++) {
  rec.append(
    build("tool_call", "reliability", {
      agent: { id: label, name: label },
      tool: "concurrency.test",
      toolInput: { worker: label, seq: i },
    }),
  );
}
