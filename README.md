# RedactChain: Proof-of-Concept Prototype for the Swift and Transparent Removal of Illicit Blockchain Content

> :warning: **Warning:** This is experimental research code for personal investigation. :warning:

Blockchains gained tremendous attention for their capability to provide immutable and decentralized event ledgers that can facilitate interactions between mutually distrusting parties.
However, precisely this immutability and the openness of permissionless blockchains raised concerns about the consequences of illicit content being irreversibly stored on them.
Related work coined the notion of redactable blockchains, which allow for removing illicit content from their history without affecting the blockchain's integrity.
While honest users can safely prune identified content, current approaches either create trust issues by empowering fixed third parties to rewrite history, cannot react quickly to reported content due to using lengthy public votings, or create large per-redaction overheads.

With _RedactChain_, we instead propose to outsource redactions to small and periodically exchanged juries, whose members can only jointly redact transactions using chameleon hash functions and threshold cryptography.
Multiple juries are active at the same time to swiftly redact reported content.
They oversee their activities via a global redaction log, which provides transparency and allows for appealing and reversing a rogue jury's decisions.
Hence, our approach establishes a framework for the swift and transparent moderation of blockchain content.
Our evaluation shows that our moderation scheme can be realized with feasible per-block and per-redaction overheads, i.e., the redaction capabilities do not impede the blockchain's normal operation.

This repository contains the experimental research code of our Python-based proof-of-concept prototype for RedactChain.

This prototype has been implemented by [Roman Matzutt](https://www.roman-matzutt.de) based on an initial version created by Vincent Ahlrichs and improved by Roman Karwacik.

### Publication

* Roman Matzutt, Vincent Ahlrichs, Jan Pennekamp, Roman Karwacik, Klaus Wehrle: A Moderation Framework for the Swift and Transparent Removal of Illicit Blockchain Content. Accepted to the 2022 IEEE International Conference on Blockchain and Cryptocurrency (ICBC'22), IEEE, 2022.

### Acknowledgments

This work has been funded by the German Federal Ministry of Education and Research (BMBF) under funding reference numbers 16KIS0443, 16DHLQ013, and Z31 BMBF Digital Campus.
The funding under reference number Z31 BMBF Digital Campus has been provided by the German Academic Exchange Service (DAAD).
The responsibility for the content of this publication lies with the authors.
The authors further thank Eric Wagner, Jan Rüth, and Muhammad Hamad Alizai for the valuable discussions.

## Usage

> :warning: **Warning:** This is experimental research code for personal investigation. :warning:

### Dependencies

All required Python libraries are listed in `requirements.txt` and can be installed via `pip`:
```
pip install -r requirements.txt
```

### First Steps

* Create a configuration file using `configgen.py`; this creates identities/credentials for a definable number of jury members as well as a chameleon hash function to be used during the redaction. For test purposes and scalability of the evaluation process (of actual redactions), the chameleon hash function is created in a centralized manner and shares for the individual jury members are drawn subsequently. During the evaluation, the peers do not read the secret trapdoor key, but only their private shares.
* General operation: `python3 peerctl.py start_all 4` (to start a jury of size four)
* For evaluation:
    * First, create an abstract transaction graph and then implement it using `python3 blockchain.py generate` and `python3 blockchain.py implement`
    * Then, you can (potentially configure the settings in `perform_eval.py` and then) run `python3 perform_eval.py`
* For further details, most scripts have a usage help to be triggered by the `-h` flag
