This little app (https://p2p-stripe-connect.wilmake.com) allows for X Login and p2p payments between X users. It uses a global durable object with SQLite to facilitate transactions, and in essence is a ledger for Stripe Connect. It allows depositing money with stripe, sending to other users, even if they're not on the platform yet, and withdrawing money using Stripe Connect.

The demo version (https://p2p-stripe-connect.wilmake.com) uses test api keys (A sandbox) so you can deposit money for free.

A next step could be coming up with a simple MCP extension to add payments to MCP tools from other X users, then creating an MCP client that has this as the basis, so we can start building MCP servers that receive payments.

Another next step could be to see if we can back the money deposited with USDC so payments can occur on a crypto platform (e.g. coinbase) such that we can use x402 as the payment protocol for MCP servers (see https://github.com/modelcontextprotocol/modelcontextprotocol/pull/2007). The benefit of starting with stripe connect is that the user experience is very smooth; nobody needs to deposit crypto! As most internet users aren't cyrpto users, this is a big plus.

Generally excited for paid MCP servers because it creates a new incentive for building actually good MCP servers besides just "look at us we have an MCP".
