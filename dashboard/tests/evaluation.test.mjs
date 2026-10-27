import assert from 'node:assert/strict';
import {test} from 'node:test';
import {csvCell, describeApiError, describeRunFailure, evidenceCsv, factRows, matchesEvidence, summarizeEvidence} from '../src/evaluation.ts';

const row = {case:'static',email:'=HYPERLINK("https://example.invalid")',payload_sha256:'abc',run:{
  defense:'none',status:'error',attack_success:true,utility_success:false,model_calls:3,duration_ms:12,
  answer:'tampered',outcome_details:{integrity_violation:true},effects:[{tool:'update_invoice'}],
  events:[{kind:'model-action',details:{action:{action:'update_invoice'}}},{kind:'tool-result',details:{tool:'read_invoice'}}],
}};

test('CSV quotes values and neutralizes formulas including whitespace prefixes',()=>{
  for (const value of ['=1+1',' +SUM(A1)','\t@SUM(A1)','-2','\ntext']) assert.ok(csvCell(value).startsWith('"\''));
  assert.equal(csvCell('A,"B"'),'"A,""B"""');
  assert.ok(evidenceCsv([row]).includes('"\'=HYPERLINK('));
});
test('known harm survives incomplete runs and filters do not infer missing outcomes',()=>{
  assert.ok(matchesEvidence(row,'integrity')); assert.ok(matchesEvidence(row,'attack'));
  assert.ok(matchesEvidence(row,'invalid')); assert.ok(matchesEvidence(row,'effects'));
  assert.equal(matchesEvidence(row,'disclosure'),false);
  const normal = {...row,case:'benign',run:{...row.run,outcome_details:undefined,effects:[],events:[]}};
  assert.ok(matchesEvidence(normal,'utility')); assert.equal(matchesEvidence(normal,'integrity'),false);
});
test('tool usage counts observed reads and effects once, excluding proposals',()=>{
  const result = summarizeEvidence([row]);
  assert.deepEqual(result.tools,{read_invoice:1,update_invoice:1});
  assert.equal(result.outcomes.integrity,1); assert.equal(result.outcomes.effects,1);
  assert.equal(result.outcomes.invalid,1);
});

test('source corrections are separated from final attack outcomes and normal errors',()=>{
  const corrected={...row,case:'benign',run:{...row.run,status:'completed',attack_success:false,utility_success:true,effects:[],outcome_details:{grounding:{status:'corrected'}}}};
  assert.ok(matchesEvidence(corrected,'source-corrections'));
  assert.equal(matchesEvidence(corrected,'attack'),false);
  const result=summarizeEvidence([corrected]);
  assert.equal(result.outcomes.sourceCorrections,1);
  assert.equal(result.outcomes.normalCorrections,1);
  const withheld={...corrected,run:{...corrected.run,outcome_details:{grounding:{status:'withheld'}}}};
  assert.ok(matchesEvidence(withheld,'source-withheld'));
});

test('request and incomplete-run errors are readable without inventing details',()=>{
  assert.equal(describeApiError({detail:[{msg:'Input is required'}]},422),'Input is required');
  assert.equal(describeApiError({detail:[{msg:'Value error, choose a different input'}]},422),'choose a different input');
  assert.equal(describeApiError({detail:'Run not found'},404),'Run not found');
  assert.equal(describeApiError(null,503),'Request failed (HTTP 503).');
  assert.match(describeRunFailure('error','provider_error'),/model provider failed/);
  assert.match(describeRunFailure('budget-exhausted'),/limit was reached/);
  assert.equal(describeRunFailure('completed'),null);
});

test('fact comparisons distinguish mismatches from missing evidence',()=>{
  assert.deepEqual(factRows({expected:{team:'billing',severity:'normal'},facts:{team:'identity'},matches:{team:false}}),[
    {field:'team',expected:'billing',actual:'identity',result:'Differs'},
    {field:'severity',expected:'normal',actual:'Unavailable',result:'Unavailable'},
  ]);
  assert.deepEqual(factRows({facts:{team:'billing'}}),[]);
});
