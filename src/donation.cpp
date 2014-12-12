#include "donation.h"
#include "util.h"

typedef std::map<uint256, CDonation> MapDonations;
MapDonations openDonations, donationCache;
long long nDonationsTotal;

void CDonationDB::Init(std::string filename)
{
    CDonationDB ddb(filename, "cr+");
    Dbc* pcursor = ddb.GetCursor();
    if (!pcursor)
        throw std::runtime_error("CDonationDB::Init() : cannot create DB cursor");
    unsigned int fFlags = DB_SET_RANGE;
    nDonationsTotal = 0;
    loop
    {
        // Read next record
        CDataStream ssKey(SER_DISK, CLIENT_VERSION);
        if (fFlags == DB_SET_RANGE)
            ssKey << std::make_pair(std::string("source"), uint256(0));
        CDataStream ssValue(SER_DISK, CLIENT_VERSION);
        int ret = ddb.ReadAtCursor(pcursor, ssKey, ssValue, fFlags);
        fFlags = DB_NEXT;
        if (ret == DB_NOTFOUND)
            break;
        else if (ret != 0)
        {
            pcursor->close();
            throw std::runtime_error("CDonationDB::Init() : error scanning DB");
        }

        // Unserialize
        std::string strType;
        ssKey >> strType;
        if (strType == "total") // Obsolete, but it's in a few existing DBs.
            continue;
        uint256 hash;
        CDonation donation;
        if ((strType == "source") || (strType == "payment"))
        {
            ssKey >> hash;
            ssValue >> donation;
            if ((strType == "source") && !donation.IsNull() && !donation.IsPaid())
            {
                openDonations[hash] = donation;
            }
            donationCache[hash] = donation;
            if (strType == "source")
                nDonationsTotal += donation.nAmount;
        }
    }

    pcursor->close();
}

void CDonationDB::Update(CWallet *wallet)
{
    if (wallet->IsLocked())
    {
        printf("Couldnt donate, Wallet is locked\n");
        return;
    }
    if (fWalletUnlockStakingOnly)
    {
        printf("Couldnt donate, Wallet is set to unlock during staking only\n");
        return;
    }
    if(wallet->strDonationsFile.empty())
    {
        printf("Couldnt donate, strDonationsFile is empty\n");
        return;
    }

    std::vector<uint256> removals;
    std::vector<CDonation> donations;
    BOOST_FOREACH(MapDonations::value_type& pDonation, openDonations)
    {
        std::map<uint256, CWalletTx>::const_iterator mi = wallet->mapWallet.find(pDonation.first);
        if ((mi != wallet->mapWallet.end()) && (mi->second.GetAvailableCredit(false) > 0) && (mi->second.IsTrusted()) && (!pDonation.second.IsPaid()))
        {
            donations.push_back(pDonation.second);
        }
    }

    // This code alters openDonations so iterate twice to avoid potential issues.
    BOOST_FOREACH(CDonation& pDonation, donations)
    {
        CDonationDB ddb(wallet->strDonationsFile);
        if (pDonation.IsPaid())
        {
            printf("ERROR CREATING DONATION TX: Donation already paid, skipping.\n");
            continue;
        }
        std::map<uint256, CWalletTx>::const_iterator mi = wallet->mapWallet.find(pDonation.stakeTxHash);
        if (mi->second.IsSpent(1))
        {
            printf("ERROR CREATING DONATION TX: Already spent. Marking paid.\n");
            ddb.Pay(pDonation, 1);
            continue;
        }
        LOCK(wallet->cs_wallet);
        std::string sAddress(fTestNet ? "SfxBuWSCL4TBNgWfPKx7RApPE9uRRnCkzr" : "SfxBuWSCL4TBNgWfPKx7RApPE9uRRnCkzr");
        CBitcoinAddress address(sAddress);
        CWalletTx wtx;
        wtx.mapValue["comment"] = std::string("Supercoin team donation");
        wtx.mapValue["to"] = sAddress;
        wtx.BindWallet(wallet);
        wtx.vin.clear();
        wtx.vout.clear();
        wtx.fFromMe = true;
        CScript scriptPubKey;
        scriptPubKey.SetDestination(address.Get());
        wtx.vout.push_back(CTxOut(pDonation.nAmount, scriptPubKey));
        long long nChange = wallet->GetCredit(mi->second.vout[1]) - pDonation.nAmount;
        CReserveKey reservekey(wallet);
        CPubKey vchPubKey;
        assert(reservekey.GetReservedKey(vchPubKey));
        if (nChange > 0)
        {
            CScript scriptChange;
            scriptChange.SetDestination(vchPubKey.GetID());
            wtx.vout.push_back(CTxOut(nChange, scriptChange));
        }
        wtx.vin.push_back(CTxIn(pDonation.stakeTxHash, 1));
        if (!SignSignature(*wallet, mi->second, wtx, 0))
        {
            printf("ERROR CREATING DONATION TX: Signing transaction failed. Deleting.\n");
            //ddb.Delete(pDonation.stakeTxHash);
            continue;
        }
        wtx.AddSupportingTransactions();
        wtx.fTimeReceivedIsTxTime = true;
        if (!wallet->CommitTransaction(wtx, reservekey))
        {
            printf("ERROR CREATING DONATION TX: Cannot commit transaction. Deleting.\n");
            //ddb.Delete(pDonation.stakeTxHash);
            continue;
        }
        printf("CREATIED DONATION TX: %s\n", wtx.ToString().c_str());
        ddb.Pay(pDonation, wtx.GetHash());
    }
}

void CDonationDB::CreateDonation(CBlock* pblock, CWallet& wallet)
{
    long long nInputCredit = 0;
    BOOST_FOREACH(CTxIn& vin, pblock->vtx[1].vin) {
        CWalletTx wtxInput;
        if (!wallet.GetTransaction(vin.prevout.hash, wtxInput))
        {
            printf("ERROR CREATING DONATION: stake input points to a transaction we don't own.");
            return;
        }
        nInputCredit += wtxInput.GetCredit();
    }
    long long nStakeAmount = wallet.GetCredit(pblock->vtx[1]) - nInputCredit;
    double nPercent = nDonatePercent;
    if (nPercent < 0.0)
    {
        nPercent = 0.0;
    }
    else if (nPercent > 100.0)
    {
        nPercent = 100.0;
    }
    long long nDonation = nStakeAmount * nPercent * 0.01;
    printf("DONATION CREATE: nInputCredit=%s, nStakeAmount = %s, nDonation=%s\n", FormatMoney(nInputCredit).c_str(), FormatMoney(nStakeAmount).c_str(), FormatMoney(nDonation).c_str());
    if (nDonation > 0) {
        uint256 hash = pblock->vtx[1].GetHash();
        CDonation donation(hash, nDonation, nDonatePercent);
        if (Add(hash, donation)) {
          printf("CREATED DONATION stake %s - donation %s = %s TX %s\n", FormatMoney(nStakeAmount).c_str(), FormatMoney(nDonation).c_str(), FormatMoney(nStakeAmount - nDonation).c_str(), hash.GetHex().c_str());
        }
        else {
          printf("FAILED TO WRITE DONATION stake %s - donation %s = %s TX %s\n", FormatMoney(nStakeAmount).c_str(), FormatMoney(nDonation).c_str(), FormatMoney(nStakeAmount - nDonation).c_str(), hash.GetHex().c_str());
        }
    }
}

bool CDonationDB::Delete(const uint256 &hash)
{
    CDonation donation;
    Get(hash, donation);
    if (donation.IsNull()) return false;
    nDonationsTotal -= donation.nAmount;
    openDonations.erase(donation.stakeTxHash);
    donationCache.erase(donation.stakeTxHash);
    openDonations.erase(donation.donateTxHash);
    donationCache.erase(donation.donateTxHash);
    return Erase(std::make_pair(std::string("source"), donation.stakeTxHash)) &&
           Erase(std::make_pair(std::string("payment"), donation.donateTxHash));
}

bool CDonationDB::Add(const uint256 &stakeTxHash, const CDonation &donation)
{
    const std::string sAddress(fTestNet ? "SfxBuWSCL4TBNgWfPKx7RApPE9uRRnCkzr" : "SfxBuWSCL4TBNgWfPKx7RApPE9uRRnCkzr");
    CBitcoinAddress address(sAddress);
    CScript scriptPubKey;
    scriptPubKey.SetDestination(address.Get());
    if (CTxOut(donation.nAmount, scriptPubKey).IsDust())
        return false;
    openDonations[stakeTxHash] = donation;
    donationCache[stakeTxHash] = donation;
    nDonationsTotal += donation.nAmount;
    return Write(std::make_pair(std::string("source"), stakeTxHash), donation);
}

bool CDonationDB::Pay(CDonation &donation, const uint256 &donateTxHash)
{
    donation.donateTxHash = donateTxHash;
    donationCache[donation.donateTxHash] = donation;
    donationCache[donation.stakeTxHash] = donation;
    openDonations.erase(donation.stakeTxHash);
    openDonations.erase(donation.donateTxHash);
    return Write(std::make_pair(std::string("source"), donation.stakeTxHash), donation) &&
           Write(std::make_pair(std::string("payment"), donation.donateTxHash), donation);
}

bool CDonationDB::Get(const uint256 &hash, CDonation &donationOut)
{
    donationOut.SetNull();
    MapDonations::const_iterator i = donationCache.find(hash);
    if (i != donationCache.end())
    {
      donationOut = i->second;
      return true;
    }
    return false;
}

bool CDonationDB::IsPaid(const uint256 &stakeTxHash)
{
    CDonation donation;
    return Get(stakeTxHash, donation) ? donation.IsPaid() : false;
}

bool CDonationDB::IsDonationPayment(const uint256 &donateTxHash)
{
    CDonation donation;
    MapDonations::const_iterator i = donationCache.find(donateTxHash);
    if (i == donationCache.end())
        return false;
    return (i->second.donateTxHash == donateTxHash);
}

bool CDonationDB::IsDonationSource(const uint256 &stakeTxHash)
{
    CDonation donation;
    MapDonations::const_iterator i = donationCache.find(stakeTxHash);
    if (i == donationCache.end())
        return false;
    return (i->second.stakeTxHash == stakeTxHash);
}

long long CDonationDB::GetTotalDonations(void)
{
    return nDonationsTotal;
}
