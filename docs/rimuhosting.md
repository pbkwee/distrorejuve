# Use RimuHosting for the new server

This is an optional destination for the [upgrade and migration workflow](ai-assisted-migration.md).
Your source can stay with its existing hosting provider during preparation. A manifest
assessment or in-place upgrade elsewhere does not need a RimuHosting account.

## Register and arrange account review

1. Open [Create a new account](https://rimuhosting.com/cp/register.jsp).
   Enter your email, contact name, password and confirmation, complete the
   challenge, accept the terms and register. Keep account credentials private.
2. Log in and open a [General support ticket](https://rimuhosting.com/ticket/startticket.jsp).
   Explain that you want a server for a migration and intend to provision it
   through the API. New accounts must contact support for the required review
   before creating VMs. Wait for support to confirm the account is ready.
3. Have the assistant [size and quote the proposed server](#size-and-quote-the-proposed-vm)
   from the source workload, performance needs and budget using the pricing API.
   Review the options and agree configuration, location, price and billing.
   Before provisioning, obtain support's account-readiness confirmation and the
   customer's approval to incur charges. Assessment and pricing can continue while account
   review is pending, once the required scoped API access is available.

For example, send this yourself through the support ticket:

> I have registered a new account and would like to use the RimuHosting API to
> create a server for a migration from another hosting provider. Please complete the
> required account review and confirm when I can create the VM.

Support can explain the review requirements for your account. No review duration
or automatic approval is promised here. Account registration and support contact
are customer actions unless explicitly delegated; giving an agent a guide does
not authorize it to create an account or send a ticket.

## Configure API access when needed

After login, use [API keys](https://rimuhosting.com/cp/apikeys.jsp) to obtain the
key for server management. Keep it in protected job-specific access storage on
the trusted operator machine. Do not paste it into a prompt, include it in a
command argument or commit it. Revoke temporary credentials when the job ends.

Use the [RimuHosting API client](https://github.com/pbkwee/RimuHostingAPI)
README for installation and configuration. It accepts `RIMUHOSTING_APIKEY` or
`.rimuhosting` settings. The settings file is executable Python: use only trusted
configuration. Prevent another job's environment or current/home/PATH settings
from selecting a different account. Protect saved responses and logs too.
The normal API endpoint is production. Follow [sensitive-data access](sensitive-data.md):
the owner should provision the designated key for the approved client, without
the agent reading `.rimuhosting` contents or printing environment values. Review
response/log handling before use; omitted authentication headers do not make
all response data safe to share.

Before provisioning, list VMs using the intended customer's key:

```bash
python3 lsvms.py --output human
```

Verify account ownership through trusted account/job records as well as the
lookup. A new account can legitimately have no VMs. An authentication or lookup
failure is not an empty inventory. Match an existing RimuHosting source to its
exact order ID and verified domain/addresses; resolve discrepancies. For a source
hosted elsewhere, record that explicit fact and its separate ownership/SSH checks.
Do not choose an unrelated VM merely because the source is absent from this account.

## Select, quote and create the approved VM

Run these catalog reads from the trusted client checkout; they currently need
no API key:

```bash
python3 lsdistros.py --output human
python3 lsdcs.py --output human
```

Choose the supported target using the common
[distro-selection criteria](upgrade-and-migration.md#choosing-a-distro-for-a-clean-install).
Verify current image/location codes, architecture, capacity, required storage,
licences and [SSH setup](ai-assisted-migration.md#arrange-ssh-discovery).

### Size and quote the proposed VM

The assistant prepares the pricing query from evidence and the customer's goals.
Do not simply copy the source's provisioned size or select the cheapest plan:

- Record current allocated RAM, CPU and disks, actual memory pressure/available
  memory and swap use, and used/free space across all relevant filesystems.
  Distinguish filesystem cache from application memory demand. Use existing
  representative peak/load history where available; one idle snapshot is not a
  peak estimate. Mark missing evidence and ask only for facts that affect sizing.
- Allow for the target OS/application requirements, expected growth, database
  work, temporary dumps/copies and upgrade headroom. Explain each allowance.
  A clone/image may require the original disk capacity even when little is used;
  do not assume it can shrink. Size a clean install from the selected migrated data.
- Relate storage and CPU choices to workload: capacity versus disk latency/IO,
  database/mail activity, CPU saturation and response-time needs. Consider changes
  such as moving mail to a managed service only when that scope is agreed.
  Confirm preferred location, monthly budget/currency and performance priorities.

Read the selected API client's help/source before constructing the query. Its
current `pricing.py` shares these options with `mkvm.py`:

| Requirement | CLI option | Field in `server.json` |
| --- | --- | --- |
| Memory | `--memory_mb` | `vps_parameters.memory_mb` in MB |
| Boot disk | `--disk_space_gb` | `vps_parameters.disk_space_mb`; CLI GB × 1024 |
| Second disk | `--disk_space_2_gb` | `vps_parameters.disk_space_2_mb`; CLI GB × 1024; zero means none |
| Location | `--dc_location` | `dc_location`, using a current catalog code |
| SSD / NVMe | `--features 'ssd'` / `--features 'nvme'` | Top-level space-separated `features` string |
| Newer CPU host | Include `recentcpu` in `--features`, e.g. `'nvme recentcpu'` | Include `recentcpu` in `features` |

`recentcpu` selects newer CPU hardware. Specify core count separately and verify
performance against the workload. Check the installed revision rather than inventing extra flags.
JSON disk sizes are MB, whereas the CLI disk options convert GB to MB.
CLI options override JSON values; `--extra_server_json` replaces matching
top-level fields rather than merging nested objects.

Use the client's [documented VM JSON format](https://github.com/pbkwee/RimuHostingAPI#configure-and-quote-a-vm)
for a private candidate file. This illustrative clean-VM configuration requests
4096 MB RAM, a 40 GB boot disk, a 20 GB second disk, NVMe and a newer CPU host.
Replace all values from the assessment and verify image/location codes:

```json
{
  "dc_location": "DCSYDNEY2",
  "instantiation_options": {
    "domain_name": "migration.example.com",
    "distro": "deb13.64"
  },
  "vps_parameters": {
    "memory_mb": 4096,
    "disk_space_mb": 40960,
    "disk_space_2_mb": 20480
  },
  "features": "nvme recentcpu"
}
```

`pricing.py` requests a quote without provisioning. Its current customized-quote
path requires the designated API key, unlike the unauthenticated catalog reads.
Use the protected credential through the client under the access rules above.
Quote the candidate file:

```bash
python3 pricing.py --server_json_file server.json --output human
```

Compare the adequate baseline with relevant alternatives, such as SSD versus
NVMe and adding `recentcpu`, when they affect performance or budget. Keep other
parameters equal to explain a feature's price difference. Use separate candidate
files and quote each; avoid an unnecessary matrix of combinations. Recommend one
with its sizing evidence, tradeoffs and budget fit. If no suitable option fits,
explain the gap rather than silently undersizing the server.

Read quote warnings/errors as well as the amount. Record the candidate, exact
query/tool revision, quote time, returned amount/currency and limitations in the
private job. Report taxes, licences, transfer, backup and support costs only as
confirmed; mark omissions and assumptions. Include temporary hosting overlap,
ongoing charges and cleanup ownership. Confirm host capacity separately before provisioning.

Before approval, write the final effective options into `server.json` and quote
that file again if any sizing, features or location changed. Do not lose CLI
overrides when handing the configuration to the creation step.

### Create the approved VM

Only after support confirms the new-account review is complete and the plan
authorizes the final configuration/costs, create from the approved file:

```bash
python3 mkvm.py --server_json_file server.json --output human
```

For a **new clean VM**, do not include `--reinstall_order_oid`, clone or saved-image
settings. `mkvm.py` can also reinstall an existing VM destructively. Verify the
payload and intended operation before sending it. Bind the returned order ID,
addresses and SSH identity to the job and verify readiness before using the VM.
For supported images, `--cloud_config FILE` can install the job's public SSH keys;
prefer Ed25519 on a clean VM and add RSA only where compatibility requires it.
Verify image support, the intended login account and each installed public key.
Otherwise arrange authorized key installation through the hosting provider's supported console/setup procedure.
Never send a private key as cloud-config.

API clone/image flags refer to RimuHosting VMs and images. They cannot clone an
arbitrary server at another hosting provider. Use a reviewed S2I restore to an isolated
prepared destination for a whole-system copy, or migrate selected applications
and data onto the clean OS. A restore overwrites files; preserve the destination's
required boot, networking and access settings using S2I's documented procedure.

After a timeout or incomplete response, check inventory and operation state
before retrying a creation or reinstall. Record exact account/order/image IDs
and authority before each later operation. Retire old or temporary VMs only after
acceptance and the agreed recovery period. Shutdown and cancellation have different
billing effects. Original-server image replacement or retained-disk attachment
needs its own verified hosting provider procedure and explicit overwrite/retention scope.

Public registration, support and API-key links checked 27 October 2026. The
new-account review prerequisite is RimuHosting's requirement supplied for this
workflow; internal review checks remain with support. Authenticated key-screen
details and live provisioning were not tested. Client command/configuration
behaviour was checked against the local RimuHosting API README and source.
