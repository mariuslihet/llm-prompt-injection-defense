import assert from 'node:assert/strict';
import {test} from 'node:test';
import {Mecha} from '../../packages/sdk-ts/src/index.ts';

test('TypeScript SDK validates inspection results and sends the requested sample', async () => {
  const original = globalThis.fetch;
  const good = {source:'tool',decision:'block',score:0.65,reasons:['instruction-override'],
    sanitized_text:'sample',sanitizer_findings:[],scope:'preview'};
  try {
    globalThis.fetch = async (url, init) => {
      assert.equal(url,'http://localhost/inspection');
      assert.deepEqual(JSON.parse(init.body),{source:'tool',content:'sample'});
      assert.equal(init.redirect,'error');
      return new Response(JSON.stringify(good),{status:200});
    };
    assert.equal((await new Mecha('http://localhost/','key').inspect('sample','tool')).decision,'block');
    globalThis.fetch = async () => new Response(JSON.stringify({...good,score:null}),{status:200});
    await assert.rejects(new Mecha('http://localhost','key').inspect('sample','tool'),/Invalid/);
    globalThis.fetch = async () => new Response(JSON.stringify({...good,source:'web'}),{status:200});
    await assert.rejects(new Mecha('http://localhost','key').inspect('sample','tool'),/Invalid/);
    globalThis.fetch = async () => new Response('',{status:503});
    await assert.rejects(new Mecha('http://localhost','key').inspect('sample','tool'),/503/);
  } finally {globalThis.fetch = original;}
});
