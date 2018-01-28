SuperCoin (SUPER)

Supercoin is a new X11 crypto coin, it has many new, original or advanced features. It uses PoW and PoS with true random SuperBlocks. It has both PoW and PoS superblocks, where it is the first coin with PoS super bonus blocks! It also uses the advanced PoW/PoS separation technology so both PoW and PoS are more stable and secure.

This is the version with p2p anonymous system, based on the multisig technology. Code developed by supercoindev.

- X11
- PoW/PoS independent
- 3 transaction confirmations 
- 50 minted block confirmations

PoW
- 90 sec PoW block time
- diff retarget each block for PoW
- Initial payout will be 512 coins per block
- True randomness, no cheat from someone with big hashpower
- Superblocks:
	- Every 3 hours there will be a block with 4X normal payment (initial 2048 coins)
	- Every day there will be a block with 16X normal payment (initial 8192 coins)
	- Every 5 days there will be a block with 128X normal payment (initial 65536 coins)

- block payout will be halved every 45 days
- minimum PoW payout for will be 1 coin/block

PoS
- 20 sec PoS block time
- diff retarget each block for PoS
- minimum hold for PoS: 1 day
- maximum hold for PoS (over which coin-day no longer accumulated): 60 days
- Variable PoS payout:
	- 1st year:  100%
	- 2nd year: 50%
	- 3rd and subsequent years: 1%

- Super-PoS-Blocks!! Only for the 1st year: 
	1 chance in 5 million coin-day (about 0.5 - 10 times per day depends on the PoS generation), that a super-PoS-block of 1024 coins on top of your regular PoS will be generated.

- Total coins will be 50,000,000.


- 5% of total PoW coins will be used for mini-IPO

- Zero premine (except for mini-IPO)


Ports: 19390 (connection), 19391 (RPC)


Development process
===========================

Developers work in their own trees, then submit pull requests when
they think their feature or bug fix is ready.

The patch will be accepted if there is broad consensus that it is a
good thing.  Developers should expect to rework and resubmit patches
if they don't match the project's coding conventions (see coding.txt)
or are controversial.

The master branch is regularly built and tested, but is not guaranteed
to be completely stable. Tags are regularly created to indicate new
stable release versions of SuperCoin.

Feature branches are created when there are major new features being
worked on by several people.

From time to time a pull request will become outdated. If this occurs, and
the pull is no longer automatically mergeable; a comment on the pull will
be used to issue a warning of closure. The pull will be closed 15 days
after the warning if action is not taken by the author. Pull requests closed
in this manner will have their corresponding issue labeled 'stagnant'.

Issues with no commits will be given a similar warning, and closed after
15 days from their last activity. Issues closed in this manner will be 
labeled 'stale'.
