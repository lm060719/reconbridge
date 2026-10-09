#include "../src/jni_bindings.h"
#include "../src/jni_exports.h"
#include "../src/jni_maps.h"
#include <cassert>
#include <iostream>

using json = nlohmann::json;
using namespace reconbridge;
static json registration(const char* identity, const char* address) {
    return {{"type","jni_registration"}, {"package","com.example.app"}, {"process_instance","42-first"},
        {"class","com.example.Native"}, {"class_id",identity}, {"method","foo"}, {"signature","(I)I"}, {"address",address}};
}
static void put(std::vector<uint8_t>& b, size_t offset, uint64_t value, size_t count) {
    for (size_t i=0; i<count; ++i) b.at(offset+i) = (value >> (i*8)) & 255;
}
static std::vector<uint8_t> elf() {
    std::vector<uint8_t> b(1024);
    put(b,0,0x464c457f,4); b[4]=2; b[5]=1; b[6]=1;
    put(b,16,3,2); put(b,18,183,2); put(b,40,64,8); put(b,58,64,2); put(b,60,3,2);
    put(b,128+4,11,4); put(b,128+24,256,8); put(b,128+32,4*24,8); put(b,128+40,2,4); put(b,128+56,24,8);
    put(b,192+4,3,4); put(b,192+24,512,8); put(b,192+32,256,8);
    const std::string symbol = "Java_com_example_Native_foo__I";
    std::copy(symbol.begin(),symbol.end(),b.begin()+513);
    for (int n=1; n<4; ++n) {
        size_t sym=256+n*24; put(b,sym,1,4); b[sym+4]=0x12;
        put(b,sym+6,1,2); put(b,sym+8,0x1234+n,8);
    }
    put(b,256+2*24+6,0,2); // undefined import excluded
    b[256+3*24+5]=2; // hidden function excluded
    return b;
}
int main(int argc, char** argv) {
    JniBindings mappings(4);
    auto snapshot = [&] (bool all=true) { return mappings.snapshot("com.example.app","",100,all); };
    mappings.ingest(registration("1","0x1000"),1);
    mappings.ingest(registration("2","0x2000"),1); // same name, different loader/class
    mappings.ingest(registration("1","0x3000"),1);
    assert(snapshot()["bindings"][0]["binding_status"] == "superseded");
    assert(snapshot(false)["count"] == 2);
    auto unreg = registration("1",""); unreg["type"] = "jni_unregistration";
    mappings.ingest(unreg,1);
    assert(snapshot(false)["count"] == 1 && snapshot()["bindings"][2]["binding_status"] == "unregistered");
    mappings.ingest(registration("1","0x4000"),2); // PID/instance reuse on new connection is isolated
    mappings.disconnect(1);
    assert(snapshot(false)["count"] == 1 && snapshot()["bindings"][1]["binding_status"] == "runtime_disconnected");
    mappings.ingest(registration("","0x5000"),2);
    assert(snapshot()["mapping_cache"]["evicted_total"] == 1);
    assert(snapshot()["bindings"][3]["binding_status"] == "identity_unknown");
    unreg["type"] = "jni_class_collected";
    mappings.ingest(unreg,2);
    assert(snapshot(false)["count"] == 0 && snapshot()["bindings"][2]["binding_status"] == "class_collected");
    assert(mappings.snapshot("another.pkg","",100,true)["count"] == 0);
    assert(mappings.snapshot("com.example.app","Native",1,true)["result_truncated"] == true);

    auto long_name = decode_jni_export("Java_p_q_A_00024Inner_do_1work__I_3Ljava_lang_String_2");
    assert(long_name["class"] == "p.q.A$Inner" && long_name["method"] == "do_work");
    assert(long_name["parameter_descriptor"] == "I[Ljava/lang/String;" && long_name["signature"].is_null());
    assert(decode_jni_export("Java_p_A_f")["parameter_descriptor"].is_null());
    assert(decode_jni_export("Java_p_A_f__")["parameter_descriptor"] == "");
    assert(jni_unescape("_04e2d_06587") == "\xe4\xb8\xad\xe6\x96\x87");
    assert(jni_unescape("_0d83d_0de00") == "\xf0\x9f\x98\x80");
    for (const auto& invalid : {"Java_foo", "Java__foo", "Java_p_A_", "Java_p_A_f_0zzzz", "Java_p_A_f_0d800"}) {
        bool caught=false; try { decode_jni_export(invalid); } catch (const std::invalid_argument&) { caught=true; }
        assert(caught);
    }
    auto bytes=elf(); auto exports=JniElf(bytes).exports("Native",10);
    assert(exports["count"] == 1 && exports["exports"][0]["elf_value"] == "0x1235");
    assert(exports["exports"][0]["binding_status"] == "export_candidate");
    assert(JniElf(bytes).exports("Other",10)["count"] == 0);
    auto two=bytes; two[256+3*24+5]=0;
    assert(JniElf(two).exports("",1)["result_truncated"] == true);
    for (int problem=0; problem<5; ++problem) {
        auto bad=bytes;
        if (problem==0) bad.resize(63);
        if (problem==1) put(bad,40,UINT64_MAX,8);
        if (problem==2) put(bad,60,0,2);
        if (problem==3) put(bad,128+40,99,4);
        if (problem==4) put(bad,256+24,999,4);
        bool caught=false; try { JniElf(bad).exports("",10); } catch (const std::invalid_argument&) { caught=true; }
        assert(caught);
    }
    const std::string maps="1000-2000 r-xp 00000000 00:01 123 /test/libsample.so\n3000-4000 rw-p 00000000 00:00 0\n";
    assert(jni_address_mapping("0x1234","/test/libsample.so",maps) == "mapped");
    assert(jni_address_mapping("0x1234","/test/other.so",maps) == "module_path_mismatch");
    assert(jni_address_mapping("0x2234","/test/libsample.so",maps) == "not_mapped");
    assert(jni_address_mapping("0x3234","",maps) == "not_executable");
    assert(jni_address_mapping("0x1234","","") == "unknown");
    if (argc > 1) {
        auto actual = inspect_jni_elf(argv[1],"",100);
        assert(actual["count"] == 2 && actual["dynamic_symbols_found"] == true);
    }
    std::cout << "JNI lifecycle, static export decoding/ELF bounds and address mapping tests passed\n";
}
