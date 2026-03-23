# GateShield Architecture

## Components
- Client
- GateShield Gateway
- Protected API
- Event Storage (later)
- Dashboard (later)

## Request Flow
1. Client sends request to gateway
2. Gateway inspects request
3. Gateway forwards request to protected API
4. Response returns to client

## Future Flow
1. Gateway evaluates rules
2. Assigns risk score
3. Decides allow / flag / block
4. Logs event