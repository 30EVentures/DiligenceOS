// Test helper: runs the JS StandInPlane from the demo spine and prints {logPub, entries} as JSON.
// Usage: node plane_log_dump.mjs <path-to-FlashyDemo>. Mock chain only; keys are generated from a fixed test seed.
import { pathToFileURL } from 'node:url'
import { join } from 'node:path'
const root = process.argv[2]
const { buildWorld } = await import(pathToFileURL(join(root, 'src/world.js')).href)
const { usd } = await import(pathToFileURL(join(root, 'src/money.js')).href)
const w = buildWorld({ seedHex: '77'.repeat(32) })
const to = w.addr('30e', 'markettrackeros')
const side = '30e'
const spend = async (amount) => {
  const { decision } = w.propose(side, 'routeros', { to, amount: usd(amount), purpose: 'test' })
  if (decision.verdict === 'ALLOW') await w.execute(side, decision.authorization, w.callFor({ to, amount: usd(amount) }))
  return decision
}
await spend('1')                       // auto-approved
const esc = w.propose(side, 'routeros', { to, amount: usd('3'), purpose: 'needs a human' })
if (esc.decision.verdict === 'ESCALATE') { const a = w.approve(side, esc.decision.requestHash); if (a.authorization) await w.execute(side, a.authorization, w.callFor({ to, amount: usd('3') })) }
await spend('6')                       // over per-tx max: DENY
const s = w.sides[side]
console.log(JSON.stringify({ logPub: s.logKey.pubHex, entries: s.plane.log.entries }))
