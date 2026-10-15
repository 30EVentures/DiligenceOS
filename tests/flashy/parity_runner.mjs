// Runs the shared refusal corpus through the JS spine (verifyInvoice, ChainReader.txOutcome).
// Used by test_parity.py via helpers.node_json: `D(path)` imports a module from the demo repo, `IN` is the corpus.
const { verifyInvoice } = await D('src/invoice.js')
const { ChainReader } = await D('src/chain.js')
const out = {}
for (const set of IN.sets) {
  for (const c of set.cases) {
    if (set.name === 'invoice') {
      let valid
      try { valid = verifyInvoice(c.invoice, c.pinned, new Date(c.now_ms)) === true } catch { valid = 'THREW' }
      out[c.id] = { valid }
    } else {
      const rpc = async (m) => { if (c.throws.includes(m)) throw new Error('rpc ' + m); return c.rpc[m] ?? null }
      try {
        const o = await new ChainReader(rpc, c.chain).txOutcome(c.txHash, c.minConfirmations)
        out[c.id] = { state: o.state, transfers: o.transfers.map((t) => ({ token: t.token ?? null, from: t.from, to: t.to, amount: String(t.amount) })) }
      } catch (e) {
        out[c.id] = { state: /allowlist|does not match/.test(String(e.message)) ? 'refused' : 'THREW', transfers: [] }
      }
    }
  }
}
console.log(JSON.stringify(out))
