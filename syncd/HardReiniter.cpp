#include "HardReiniter.h"
#include "VidManager.h"
#include "SingleReiniter.h"
#include "BaseRedisClient.h"

#include "swss/logger.h"

#include "meta/sai_serialize.h"

using namespace syncd;

HardReiniter::HardReiniter(
        _In_ std::shared_ptr<BaseRedisClient> client,
        _In_ std::shared_ptr<VirtualOidTranslator> translator,
        _In_ std::shared_ptr<sairedis::SaiInterface> sai,
        _In_ std::shared_ptr<NotificationHandler> handler):
    m_vendorSai(sai),
    m_translator(translator),
    m_client(client),
    m_handler(handler)
{
    SWSS_LOG_ENTER();

    // empty
}

HardReiniter::~HardReiniter()
{
    SWSS_LOG_ENTER();

    // empty
}

void HardReiniter::readAsicState()
{
    SWSS_LOG_ENTER();

    SWSS_LOG_TIMER("read asic state");

    /*
     * Read VIDTORID, RIDTOVID and ASIC_STATE keys as a single atomic Redis
     * MULTI/EXEC transaction.
     *
     * Without atomicity, swss can flush ASIC_DB between any two of the three
     * reads, producing a partially-stale snapshot where ASIC_STATE still shows
     * the switch but the VID/RID maps are already empty.  hardReinit() would
     * then call m_switchVidToRid.at(switchVid) on a missing key and throw
     * std::out_of_range, or continue reinitializing from inconsistent RID
     * references.
     *
     * With MULTI/EXEC the three reads are serialized at the Redis level: no
     * other client command (including a swss DEL VIDTORID) can interleave
     * between them.
     */
    auto snap = m_client->getAsicStateAtomicSnapshot();

    m_vidToRidMap = std::move(snap.vidToRid);
    m_ridToVidMap = std::move(snap.ridToVid);

    for (auto& v2r: m_vidToRidMap)
    {
        auto switchId = VidManager::switchIdQuery(v2r.first);

        m_switchVidToRid[switchId][v2r.first] = v2r.second;
    }

    for (auto& r2v: m_ridToVidMap)
    {
        auto switchId = VidManager::switchIdQuery(r2v.second);

        m_switchRidToVid[switchId][r2v.first] = r2v.second;
    }

    auto asicStateKeys = std::move(snap.asicStateKeys);

    for (const auto &key: asicStateKeys)
    {
        auto mk = key.substr(key.find_first_of(":") + 1); // skip asic key

        sai_object_meta_key_t metaKey;
        sai_deserialize_object_meta_key(mk, metaKey);

        // if object is non object id then first item will be switch id

        auto switchId = VidManager::switchIdQuery(metaKey.objectkey.key.object_id);

        m_switchMap[switchId].push_back(key);
    }

    SWSS_LOG_NOTICE("loaded %zu switches", m_switchMap.size());

    for (auto& kvp: m_switchMap)
    {
        SWSS_LOG_NOTICE("switch VID: %s", sai_serialize_object_id(kvp.first).c_str());
    }

    /*
     * Consistency check: every switch VID present in ASIC_STATE must also
     * have an entry in the VID→RID map.  If any entry is missing it means
     * swss started flushing ASIC_DB between our three Redis reads (keys,
     * VIDTORID, RIDTOVID) and the snapshot is therefore partially stale.
     *
     * Using inconsistent maps would cause hardReinit() to throw an
     * unhandled std::out_of_range when it calls m_switchVidToRid.at() for
     * a switch VID that is absent from the map, or—worse—to attempt to
     * recreate SAI objects using wrong RID references.
     *
     * Safe recovery: clear all switch maps so the hardReinit() loop is a
     * no-op.  Syncd will then start with an empty view and wait for
     * orchagent to push the initial configuration, exactly as it would on
     * a first-time cold boot.
     */
    for (auto& kvp: m_switchMap)
    {
        sai_object_id_t switchVid = kvp.first;

        if (m_switchVidToRid.find(switchVid) == m_switchVidToRid.end())
        {
            SWSS_LOG_WARN("ASIC_DB consistency check failed: switch VID %s "
                          "is in ASIC_STATE but missing from VIDTORID map. "
                          "ASIC_DB was partially flushed during read. "
                          "Skipping hard reinit and waiting for orchagent.",
                          sai_serialize_object_id(switchVid).c_str());

            m_switchMap.clear();
            m_switchVidToRid.clear();
            m_switchRidToVid.clear();
            return;
        }
    }
}

std::map<sai_object_id_t, std::shared_ptr<syncd::SaiSwitch>> HardReiniter::hardReinit()
{
    SWSS_LOG_ENTER();

    readAsicState();

    std::vector<std::shared_ptr<SingleReiniter>> vec;

    // perform hard reinit on all switches

    for (auto& kvp: m_switchMap)
    {
        auto sr = std::make_shared<SingleReiniter>(
                m_client,
                m_translator,
                m_vendorSai,
                m_handler,
                m_switchVidToRid.at(kvp.first),
                m_switchRidToVid.at(kvp.first),
                kvp.second);

        sr->hardReinit();

        vec.push_back(sr);
    }

    // since vid and rid maps contains all switches
    // we need to combine them

    ObjectIdMap vid2rid;
    ObjectIdMap rid2vid;

    for (auto&sr: vec)
    {
        auto map = sr->getTranslatedVid2Rid();

        for (auto&kvp: map)
        {
            vid2rid[kvp.first] = kvp.second;
            rid2vid[kvp.second] = kvp.first;
        }
    }

    if (vid2rid.size() != rid2vid.size())
    {
        SWSS_LOG_THROW("FATAL: vid2rid %zu != rid2vid %zu",
                vid2rid.size(),
                rid2vid.size());
    }

    // now some object could be removed from switch then we need to execute
    // post actions, and since those actions will be executed on switches which
    // will also modify redis database we need to execute this after we put vid
    // and rid map

    /*
     * NOTE: clear can be done after recreating all switches unless vid/rid map
     * will be per switch. An all this must be ATOMIC.
     *
     * This needs to be addressed when we want to support multiple switches.
     */

    m_client->setVidAndRidMap(vid2rid);

    std::map<sai_object_id_t, std::shared_ptr<syncd::SaiSwitch>> switches;

    for (auto& sr: vec)
    {
        sr->postRemoveActions();

        auto sw = sr->getSwitch();

        switches[sw->getVid()] = sw;
    }

    return switches;
}
