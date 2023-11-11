# Heimbjartur

## Building

The project requires the following dependencies to build:

- A relatively new Linux kernel version (>= 5.15) that has the `kfree_skb_reason` kernel function
- The Rust programming language (1.71)
- LLVM 16

You can view the `.devcontainer/Containerfile.dev` for more information abou dependencies

To build the eBPF part run: 

```bash
$ cargo kprobe
```

And to build Heimbjartur run:

```bash
$ cargo heimbjartur
```

## Running

To run a single use the following command:

```bash
$ sudo ./target/debug/heimbjartur --binary target/bpfel-unknown-none/debug/kprobe single -s <SRC_IP>:<SRC_PORT> -d <DST_IP>:<DST_PORT> -p [tcp, udp]
```

Or to run multiple tests

```bash
sudo ./target/debug/heimbjartur --binary target/bpfel-unknown-none/debug/kprobe multiple --file_name rules.txt
```

Where `rules.txt` contains:

```
1.1.1.1:10000 2.2.2.2:10000 tcp
1.1.1.1:20000 2.2.2.2:20000 udp
```
