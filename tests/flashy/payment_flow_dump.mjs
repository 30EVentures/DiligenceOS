// Test helper: one full authorized-and-made payment on the demo spine's MOCK chain, dumped as JSON.
// Usage: node payment_flow_dump.mjs <path-to-FlashyDemo> [amount-in-dollars]. Keys come from a fixed test seed. No network, no funds.
import { pathToFileURL } from 'node:url'
import { join } from 'node:path'
const root = process.argv[2]
const amount = process.argv[3] ?? '1'
const imp = (p) => import(pathToFileURL(join(root, p)).href)
const { buildWorld } = await imp('src/world.js')
const { usd } = await imp('src/money.js')
const { makeSpendRequest } = await imp('src/plane.js')
const w = buildWorld({ seedHex: '77'.repeat(32) })
const side = '30e'
const s = w.sides[side]
const buyer = s.agents.get('routeros'), seller = w.agent(side, 'markettrackeros')
const to = seller.acct.address
const req = makeSpendRequest(buyer.key, { requestId: 'r-evidence-1', grantChain: buyer.grants, spend: { kind: 'transfer', chain: 'evm:31337', asset: w.token, amount: usd(amount), destination: to }, purpose: 'pay for one sealed snapshot', issuedAt: w.clock().toISOString() })
const decision = s.plane.request(req)
if (decision.verdict !== 'ALLOW') throw new Error('not allowed: ' + JSON.stringify(decision))
const result = await w.execute(side, decision.authorization, w.callFor({ to, amount: usd(amount) }))   // also reports the signed outcome back to the plane
const txHash = result.txHash
const rpc = (m, p) => w.chain.rpc(m, p)
console.log(JSON.stringify({
  planePub: s.planeKey.pubHex, logPub: s.logKey.pubHex, rootPubs: [s.root.pubHex], agentPub: buyer.key.pubHex,
  request: req, authorization: decision.authorization, entries: s.plane.log.entries, txHash,
  chain: { id: await rpc('eth_chainId', []), tip: await rpc('eth_blockNumber', []), receipt: await rpc('eth_getTransactionReceipt', [txHash]) },
  payer: buyer.acct.address, payee: to, asset: w.token, amount: usd(amount),
}))
