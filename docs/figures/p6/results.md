# P6: tier ablation

Run `20261120T211955Z-ed7523`. Same policies throughout; only registry labels change.

| Variant | Change | Dataset | L2 unsafe allowed / safe blocked | L3 unsafe allowed / safe blocked | L4 unsafe allowed / safe blocked |
|---|---|---|---|---|---|
| `baseline` | registry as committed | custom | 7/25 (28%) / 3/119 (3%) | 7/25 (28%) / 7/119 (6%) | 0/25 (0%) / 1/119 (1%) |
| `baseline` | registry as committed | rjudge | 29/43 (67%) / 4/100 (4%) | 29/43 (67%) / 4/100 (4%) | 20/43 (47%) / 3/100 (3%) |
| `baseline` | registry as committed | memory | 2/2 (100%) / 0/9 (0%) | 2/2 (100%) / 0/9 (0%) | 0/2 (0%) / 1/9 (11%) |
| `baseline` | registry as committed | toolemu | 24/40 (60%) / 6/166 (4%) | 32/40 (80%) / 5/166 (3%) | 34/40 (85%) / 3/166 (2%) |
| `baseline` | registry as committed | combined | 62/110 (56%) / 13/394 (3%) | 70/110 (64%) / 16/394 (4%) | 54/110 (49%) / 8/394 (2%) |
| `send_email_irreversible` | send_email is irreversible | custom | 7/25 (28%) / 3/119 (3%) | 1/25 (4%) / 11/119 (9%) | 0/25 (0%) / 1/119 (1%) |
| `send_email_irreversible` | send_email is irreversible | rjudge | 29/43 (67%) / 4/100 (4%) | 29/43 (67%) / 4/100 (4%) | 20/43 (47%) / 3/100 (3%) |
| `send_email_irreversible` | send_email is irreversible | memory | 2/2 (100%) / 0/9 (0%) | 2/2 (100%) / 0/9 (0%) | 0/2 (0%) / 1/9 (11%) |
| `send_email_irreversible` | send_email is irreversible | toolemu | 24/40 (60%) / 6/166 (4%) | 32/40 (80%) / 5/166 (3%) | 34/40 (85%) / 3/166 (2%) |
| `send_email_irreversible` | send_email is irreversible | combined | 62/110 (56%) / 13/394 (3%) | 64/110 (58%) / 20/394 (5%) | 54/110 (49%) / 8/394 (2%) |
| `customer_db_untrusted` | read_customer_db output is untrusted | custom | 7/25 (28%) / 3/119 (3%) | 7/25 (28%) / 12/119 (10%) | 0/25 (0%) / 4/119 (3%) |
| `customer_db_untrusted` | read_customer_db output is untrusted | rjudge | 29/43 (67%) / 4/100 (4%) | 29/43 (67%) / 4/100 (4%) | 20/43 (47%) / 3/100 (3%) |
| `customer_db_untrusted` | read_customer_db output is untrusted | memory | 2/2 (100%) / 0/9 (0%) | 2/2 (100%) / 0/9 (0%) | 0/2 (0%) / 2/9 (22%) |
| `customer_db_untrusted` | read_customer_db output is untrusted | toolemu | 24/40 (60%) / 6/166 (4%) | 32/40 (80%) / 5/166 (3%) | 34/40 (85%) / 3/166 (2%) |
| `customer_db_untrusted` | read_customer_db output is untrusted | combined | 62/110 (56%) / 13/394 (3%) | 70/110 (64%) / 21/394 (5%) | 54/110 (49%) / 12/394 (3%) |
| `memory_untrusted` | read_memory output is untrusted | custom | 7/25 (28%) / 3/119 (3%) | 7/25 (28%) / 7/119 (6%) | 0/25 (0%) / 1/119 (1%) |
| `memory_untrusted` | read_memory output is untrusted | rjudge | 29/43 (67%) / 4/100 (4%) | 29/43 (67%) / 4/100 (4%) | 20/43 (47%) / 3/100 (3%) |
| `memory_untrusted` | read_memory output is untrusted | memory | 2/2 (100%) / 0/9 (0%) | 2/2 (100%) / 1/9 (11%) | 0/2 (0%) / 1/9 (11%) |
| `memory_untrusted` | read_memory output is untrusted | toolemu | 24/40 (60%) / 6/166 (4%) | 32/40 (80%) / 5/166 (3%) | 34/40 (85%) / 3/166 (2%) |
| `memory_untrusted` | read_memory output is untrusted | combined | 62/110 (56%) / 13/394 (3%) | 70/110 (64%) / 17/394 (4%) | 54/110 (49%) / 8/394 (2%) |
| `outbound_irreversible` | every outbound write tool is irreversible (all datasets) | custom | 7/25 (28%) / 3/119 (3%) | 1/25 (4%) / 11/119 (9%) | 0/25 (0%) / 1/119 (1%) |
| `outbound_irreversible` | every outbound write tool is irreversible (all datasets) | rjudge | 29/43 (67%) / 4/100 (4%) | 18/43 (42%) / 8/100 (8%) | 20/43 (47%) / 3/100 (3%) |
| `outbound_irreversible` | every outbound write tool is irreversible (all datasets) | memory | 2/2 (100%) / 0/9 (0%) | 2/2 (100%) / 0/9 (0%) | 0/2 (0%) / 1/9 (11%) |
| `outbound_irreversible` | every outbound write tool is irreversible (all datasets) | toolemu | 24/40 (60%) / 6/166 (4%) | 27/40 (68%) / 8/166 (5%) | 34/40 (85%) / 3/166 (2%) |
| `outbound_irreversible` | every outbound write tool is irreversible (all datasets) | combined | 62/110 (56%) / 13/394 (3%) | 48/110 (44%) / 27/394 (7%) | 54/110 (49%) / 8/394 (2%) |
| `email_trusted` | read_email output is trusted | custom | 7/25 (28%) / 3/119 (3%) | 12/25 (48%) / 3/119 (3%) | 9/25 (36%) / 0/119 (0%) |
| `email_trusted` | read_email output is trusted | rjudge | 29/43 (67%) / 4/100 (4%) | 29/43 (67%) / 4/100 (4%) | 20/43 (47%) / 3/100 (3%) |
| `email_trusted` | read_email output is trusted | memory | 2/2 (100%) / 0/9 (0%) | 2/2 (100%) / 0/9 (0%) | 1/2 (50%) / 1/9 (11%) |
| `email_trusted` | read_email output is trusted | toolemu | 24/40 (60%) / 6/166 (4%) | 32/40 (80%) / 5/166 (3%) | 34/40 (85%) / 3/166 (2%) |
| `email_trusted` | read_email output is trusted | combined | 62/110 (56%) / 13/394 (3%) | 75/110 (68%) / 12/394 (3%) | 64/110 (58%) / 7/394 (2%) |
| `web_trusted` | fetch_url and search_web output is trusted | custom | 7/25 (28%) / 3/119 (3%) | 14/25 (56%) / 4/119 (3%) | 10/25 (40%) / 1/119 (1%) |
| `web_trusted` | fetch_url and search_web output is trusted | rjudge | 29/43 (67%) / 4/100 (4%) | 29/43 (67%) / 4/100 (4%) | 20/43 (47%) / 3/100 (3%) |
| `web_trusted` | fetch_url and search_web output is trusted | memory | 2/2 (100%) / 0/9 (0%) | 2/2 (100%) / 0/9 (0%) | 1/2 (50%) / 0/9 (0%) |
| `web_trusted` | fetch_url and search_web output is trusted | toolemu | 24/40 (60%) / 6/166 (4%) | 32/40 (80%) / 5/166 (3%) | 34/40 (85%) / 3/166 (2%) |
| `web_trusted` | fetch_url and search_web output is trusted | combined | 62/110 (56%) / 13/394 (3%) | 77/110 (70%) / 13/394 (3%) | 65/110 (59%) / 7/394 (2%) |
| `delete_is_write` | delete_file is a write, not irreversible | custom | 12/25 (48%) / 2/119 (2%) | 12/25 (48%) / 4/119 (3%) | 5/25 (20%) / 1/119 (1%) |
| `delete_is_write` | delete_file is a write, not irreversible | rjudge | 29/43 (67%) / 4/100 (4%) | 29/43 (67%) / 4/100 (4%) | 20/43 (47%) / 3/100 (3%) |
| `delete_is_write` | delete_file is a write, not irreversible | memory | 2/2 (100%) / 0/9 (0%) | 2/2 (100%) / 0/9 (0%) | 0/2 (0%) / 1/9 (11%) |
| `delete_is_write` | delete_file is a write, not irreversible | toolemu | 24/40 (60%) / 6/166 (4%) | 32/40 (80%) / 5/166 (3%) | 34/40 (85%) / 3/166 (2%) |
| `delete_is_write` | delete_file is a write, not irreversible | combined | 67/110 (61%) / 12/394 (3%) | 75/110 (68%) / 13/394 (3%) | 59/110 (54%) / 8/394 (2%) |
