// Tutorial 5: the OAI LTE UE's subscription (OAI CI USIM: IMSI 208960100000001), APN oai.ipv4 on QCI 9, and the PCC rule
// with QCI 65 (MCPTT voice, GBR) that the PCRF uses for the AUDIO media component of an MCPTT AF session.
db.subscribers.deleteMany({ imsi: "208960100000001" });
db.subscribers.insertOne({
  imsi: "208960100000001",
  msisdn: [], imeisv: "", mme_host: [], mme_realm: [], purge_flag: [],
  security: { k: "fec86ba6eb707ed08905757b1bb44b8f", op: null, opc: "c42449363bbad02b66d16bc975d77cc1", amf: "8000", sqn: NumberLong("64") },
  ambr: { downlink: { value: 1, unit: 3 }, uplink: { value: 1, unit: 3 } },
  slice: [{
    sst: 1, default_indicator: true,
    session: [{
      name: "oai.ipv4", type: 1,
      qos: { index: 9, arp: { priority_level: 8, pre_emption_capability: 1, pre_emption_vulnerability: 1 } },
      ambr: { downlink: { value: 1, unit: 3 }, uplink: { value: 1, unit: 3 } },
      pcc_rule: [{
        qos: {
          index: 65, arp: { priority_level: 2, pre_emption_capability: 2, pre_emption_vulnerability: 2 },
          mbr: { downlink: { value: 128, unit: 1 }, uplink: { value: 128, unit: 1 } },
          gbr: { downlink: { value: 128, unit: 1 }, uplink: { value: 128, unit: 1 } }
        },
        flow: []
      }]
    }]
  }],
  access_restriction_data: 32, subscriber_status: 0, network_access_mode: 0, subscribed_rau_tau_timer: 12, __v: 0
});
print(db.subscribers.countDocuments({ imsi: "208960100000001" }));
