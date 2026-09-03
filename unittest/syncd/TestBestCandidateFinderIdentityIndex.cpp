#include "BestCandidateFinder.h"
#include "MockableSaiSwitchInterface.h"

#include "meta/sai_serialize.h"

#include "swss/logger.h"

#include <gtest/gtest.h>

#include <vector>

using namespace syncd;
using namespace unittests;

namespace
{
    struct TestOidPair
    {
        sai_object_id_t vid;
        sai_object_id_t rid;
    };

    TestOidPair deserializePair(
            _In_ const char *vidStr,
            _In_ const char *ridStr)
    {
        SWSS_LOG_ENTER();

        TestOidPair pair;

        sai_deserialize_object_id(vidStr, pair.vid);
        sai_deserialize_object_id(ridStr, pair.rid);

        return pair;
    }

    std::shared_ptr<SaiObj> addOidObject(
            _Inout_ AsicView &view,
            _In_ const TestOidPair &ids,
            _In_ const std::vector<std::pair<const char*, const char*>> &attrs)
    {
        SWSS_LOG_ENTER();

        auto obj = view.createDummyExistingObject(ids.rid, ids.vid);

        for (const auto &attr: attrs)
        {
            obj->setAttr(std::make_shared<SaiAttr>(attr.first, attr.second));
        }

        return obj;
    }
}

TEST(BestCandidateFinderIdentityIndex, buildAttrFilterFromObject_SkipsReadOnly)
{
    AsicView view;

    const auto ids = deserializePair("oid:0x4000000000912", "oid:0x400000000040");

    auto nh = addOidObject(view, ids, {
        {"SAI_NEXT_HOP_ATTR_TYPE", "SAI_NEXT_HOP_TYPE_IP"},
        {"SAI_NEXT_HOP_ATTR_IP", "10.0.0.9"},
    });

    const auto filter = BestCandidateFinder::buildAttrFilterFromObject(nh);

    EXPECT_EQ(filter.size(), 2u);
    EXPECT_NE(filter.find(SAI_NEXT_HOP_ATTR_TYPE), filter.end());
    EXPECT_NE(filter.find(SAI_NEXT_HOP_ATTR_IP), filter.end());
}

TEST(BestCandidateFinderIdentityIndex, findCurrentBestMatchUsingIdentityIndex)
{
    AsicView currentView;
    AsicView tempView;

    const auto curIds = deserializePair("oid:0x4000000000913", "oid:0x400000000050");
    const auto tmpIds = deserializePair("oid:0x4000000000914", "oid:0x400000000050");

    addOidObject(currentView, curIds, {
        {"SAI_NEXT_HOP_ATTR_TYPE", "SAI_NEXT_HOP_TYPE_IP"},
        {"SAI_NEXT_HOP_ATTR_IP", "10.0.0.10"},
    });

    auto tmpNh = addOidObject(tempView, tmpIds, {
        {"SAI_NEXT_HOP_ATTR_TYPE", "SAI_NEXT_HOP_TYPE_IP"},
        {"SAI_NEXT_HOP_ATTR_IP", "10.0.0.10"},
    });

    auto sw = std::make_shared<MockableSaiSwitchInterface>(0, 0);
    BestCandidateFinder bcf(currentView, tempView, sw);

    auto match = bcf.findCurrentBestMatchUsingIdentityIndex(tmpNh);

    ASSERT_NE(match, nullptr);
    EXPECT_EQ(match->getVid(), curIds.vid);
}

TEST(BestCandidateFinderIdentityIndex, findCurrentBestMatchUsingIdentityIndex_DuplicateAclTableGroupsFallThrough)
{
    AsicView currentView;
    AsicView tempView;

    const auto cur1 = deserializePair("oid:0xb000000000001", "oid:0xb000000000010");
    const auto cur2 = deserializePair("oid:0xb000000000002", "oid:0xb000000000011");
    const auto tmpIds = deserializePair("oid:0xb000000000003", "oid:0xb000000000012");

    const std::vector<std::pair<const char*, const char*>> atgAttrs = {
        {"SAI_ACL_TABLE_GROUP_ATTR_ACL_STAGE", "SAI_ACL_STAGE_INGRESS"},
        {"SAI_ACL_TABLE_GROUP_ATTR_ACL_BIND_POINT_TYPE_LIST", "1:SAI_ACL_BIND_POINT_TYPE_PORT"},
        {"SAI_ACL_TABLE_GROUP_ATTR_TYPE", "SAI_ACL_TABLE_GROUP_TYPE_PARALLEL"},
    };

    addOidObject(currentView, cur1, atgAttrs);
    addOidObject(currentView, cur2, atgAttrs);

    auto tmpAtg = addOidObject(tempView, tmpIds, atgAttrs);

    auto sw = std::make_shared<MockableSaiSwitchInterface>(0, 0);
    BestCandidateFinder bcf(currentView, tempView, sw);

    auto match = bcf.findCurrentBestMatchUsingIdentityIndex(tmpAtg);

    EXPECT_EQ(match, nullptr);
}

TEST(BestCandidateFinderIdentityIndex, findCurrentBestMatchForNextHopGroupUsingMemberIndex)
{
    AsicView currentView;
    AsicView tempView;

    const auto curNhg = deserializePair("oid:0x5000000002caf", "oid:0x500000000020");
    const auto tmpNhg = deserializePair("oid:0x5000000002cb0", "oid:0x500000000020");
    const auto curNh = deserializePair("oid:0x4000000000915", "oid:0x400000000060");
    const auto tmpNh = deserializePair("oid:0x4000000000916", "oid:0x400000000060");

    addOidObject(currentView, curNhg, {
        {"SAI_NEXT_HOP_GROUP_ATTR_TYPE", "SAI_NEXT_HOP_GROUP_TYPE_DYNAMIC_UNORDERED_ECMP"},
    });

    addOidObject(currentView, curNh, {
        {"SAI_NEXT_HOP_ATTR_TYPE", "SAI_NEXT_HOP_TYPE_IP"},
        {"SAI_NEXT_HOP_ATTR_IP", "10.0.0.11"},
    });

    addOidObject(currentView, deserializePair("oid:0x2d000000002cb0", "oid:0x2d000000000020"), {
        {"SAI_NEXT_HOP_GROUP_MEMBER_ATTR_NEXT_HOP_GROUP_ID", "oid:0x5000000002caf"},
        {"SAI_NEXT_HOP_GROUP_MEMBER_ATTR_NEXT_HOP_ID", "oid:0x4000000000915"},
    });

    auto tmpNhgObj = addOidObject(tempView, tmpNhg, {
        {"SAI_NEXT_HOP_GROUP_ATTR_TYPE", "SAI_NEXT_HOP_GROUP_TYPE_DYNAMIC_UNORDERED_ECMP"},
    });

    addOidObject(tempView, tmpNh, {
        {"SAI_NEXT_HOP_ATTR_TYPE", "SAI_NEXT_HOP_TYPE_IP"},
        {"SAI_NEXT_HOP_ATTR_IP", "10.0.0.11"},
    });

    addOidObject(tempView, deserializePair("oid:0x2d000000002cb1", "oid:0x2d000000000021"), {
        {"SAI_NEXT_HOP_GROUP_MEMBER_ATTR_NEXT_HOP_GROUP_ID", "oid:0x5000000002cb0"},
        {"SAI_NEXT_HOP_GROUP_MEMBER_ATTR_NEXT_HOP_ID", "oid:0x4000000000916"},
    });

    tempView.m_vidToRid[tmpNh.vid] = curNh.rid;

    auto sw = std::make_shared<MockableSaiSwitchInterface>(0, 0);
    BestCandidateFinder bcf(currentView, tempView, sw);

    auto match = bcf.findCurrentBestMatchForNextHopGroupUsingMemberIndex(tmpNhgObj);

    ASSERT_NE(match, nullptr);
    EXPECT_EQ(match->getVid(), curNhg.vid);
}

TEST(BestCandidateFinderIdentityIndex, findCurrentBestMatchForGenericObject_NhgmSameRidDifferentVid)
{
    AsicView currentView;
    AsicView tempView;

    const auto curNhg = deserializePair("oid:0x5000000002cb2", "oid:0x500000000030");
    const auto tmpNhg = deserializePair("oid:0x5000000002cb3", "oid:0x500000000030");
    const auto curNh = deserializePair("oid:0x4000000000917", "oid:0x400000000070");
    const auto tmpNh = deserializePair("oid:0x4000000000918", "oid:0x400000000070");
    const auto curNhgm = deserializePair("oid:0x2d000000002cb2", "oid:0x2d000000000030");
    const auto tmpNhgm = deserializePair("oid:0x2d000000002cb3", "oid:0x2d000000000031");

    addOidObject(currentView, curNhg, {
        {"SAI_NEXT_HOP_GROUP_ATTR_TYPE", "SAI_NEXT_HOP_GROUP_TYPE_DYNAMIC_UNORDERED_ECMP"},
    });

    addOidObject(currentView, curNh, {
        {"SAI_NEXT_HOP_ATTR_TYPE", "SAI_NEXT_HOP_TYPE_IP"},
        {"SAI_NEXT_HOP_ATTR_IP", "10.0.0.12"},
    });

    addOidObject(currentView, curNhgm, {
        {"SAI_NEXT_HOP_GROUP_MEMBER_ATTR_NEXT_HOP_GROUP_ID", "oid:0x5000000002cb2"},
        {"SAI_NEXT_HOP_GROUP_MEMBER_ATTR_NEXT_HOP_ID", "oid:0x4000000000917"},
    });

    auto tmpNhgmObj = addOidObject(tempView, tmpNhgm, {
        {"SAI_NEXT_HOP_GROUP_MEMBER_ATTR_NEXT_HOP_GROUP_ID", "oid:0x5000000002cb3"},
        {"SAI_NEXT_HOP_GROUP_MEMBER_ATTR_NEXT_HOP_ID", "oid:0x4000000000918"},
    });

    tempView.m_vidToRid[tmpNhg.vid] = curNhg.rid;
    tempView.m_vidToRid[tmpNh.vid] = curNh.rid;

    auto sw = std::make_shared<MockableSaiSwitchInterface>(0, 0);
    BestCandidateFinder bcf(currentView, tempView, sw);

    auto match = bcf.findCurrentBestMatchForGenericObject(tmpNhgmObj);

    ASSERT_NE(match, nullptr);
    EXPECT_EQ(match->getVid(), curNhgm.vid);
}

TEST(BestCandidateFinderIdentityIndex, findCurrentBestMatchForGenericObject_NhgmDifferentRidRejected)
{
    AsicView currentView;
    AsicView tempView;

    const auto curNhg = deserializePair("oid:0x5000000002cb4", "oid:0x500000000040");
    const auto tmpNhg = deserializePair("oid:0x5000000002cb5", "oid:0x500000000040");
    const auto curNh = deserializePair("oid:0x4000000000919", "oid:0x400000000080");
    const auto tmpNh = deserializePair("oid:0x400000000091a", "oid:0x400000000081");
    const auto curNhgm = deserializePair("oid:0x2d000000002cb4", "oid:0x2d000000000040");
    const auto tmpNhgm = deserializePair("oid:0x2d000000002cb5", "oid:0x2d000000000041");

    addOidObject(currentView, curNhg, {
        {"SAI_NEXT_HOP_GROUP_ATTR_TYPE", "SAI_NEXT_HOP_GROUP_TYPE_DYNAMIC_UNORDERED_ECMP"},
    });

    addOidObject(currentView, curNh, {
        {"SAI_NEXT_HOP_ATTR_TYPE", "SAI_NEXT_HOP_TYPE_IP"},
        {"SAI_NEXT_HOP_ATTR_IP", "10.0.0.13"},
    });

    addOidObject(currentView, curNhgm, {
        {"SAI_NEXT_HOP_GROUP_MEMBER_ATTR_NEXT_HOP_GROUP_ID", "oid:0x5000000002cb4"},
        {"SAI_NEXT_HOP_GROUP_MEMBER_ATTR_NEXT_HOP_ID", "oid:0x4000000000919"},
    });

    auto tmpNhgmObj = addOidObject(tempView, tmpNhgm, {
        {"SAI_NEXT_HOP_GROUP_MEMBER_ATTR_NEXT_HOP_GROUP_ID", "oid:0x5000000002cb5"},
        {"SAI_NEXT_HOP_GROUP_MEMBER_ATTR_NEXT_HOP_ID", "oid:0x400000000091a"},
    });

    tempView.m_vidToRid[tmpNhg.vid] = curNhg.rid;
    tempView.m_vidToRid[tmpNh.vid] = tmpNh.rid;

    auto sw = std::make_shared<MockableSaiSwitchInterface>(0, 0);
    BestCandidateFinder bcf(currentView, tempView, sw);

    auto match = bcf.findCurrentBestMatchForGenericObject(tmpNhgmObj);

    EXPECT_EQ(match, nullptr);
}
