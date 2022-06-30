//auto create contract
#include <stdlib.h>
#include <string.h>
#include <string>
#include <time.h>
#include <ctime>
#include <bcwasm/bcwasm.hpp>
#include <vector>
#include <tuple>
#include <rapidjson/document.h>
#include <rapidjson/prettywriter.h>
#include <rapidjson/writer.h>
#include <rapidjson/stringbuffer.h>
using namespace std;
using namespace rapidjson;
using namespace bcwasm;

namespace did
{
	enum BpStatus
	{
		Valid,
		Expired,
		Revoked
	};

	struct BProof
	{
		string bpid;
		string did;
		string proof;
		string range;
		BpStatus status;
		BCWASM_SERIALIZE(BProof, (bpid)(did)(proof)(range)(status));
	};

	char bpMapName[] = "BpMap";

	class bullet_proof : public bcwasm::Contract
	{
	public:bullet_proof(){}

		/// 实现父类: bcwasm::Contract 的虚函数
		/// 该函数在合约首次发布时执行，仅调用一次
		void init()
		{
			bcwasm::println("init  success...");
		}
		/// 定义Event.
		/// BCWASM_EVENT(eventName, arguments...)
		BCWASM_EVENT(Notify, const char *, int)

	public:
		bool ensurePermissionByDid(const char *did) const
		{
			bcwasm::DeployedContract identityContract(
				"0x6FB6263c58Ed4cf8FB20A773233fC6DB41c77dE3");
			int64_t res = identityContract.callInt64("ensurePermissionByDid", did);
			return res == 1;
		}

		void create_proof(const char *bpid, const char *did, const char *proof, const char *range)
		{
			BProof *bproof = BpMap.find(bpid);
			if (ensurePermissionByDid(did))
			{
				if (bproof == nullptr)
				{
					BProof tempBProof;
					tempBProof.bpid = bpid;
					tempBProof.did = did;
					tempBProof.proof = proof;
					tempBProof.range = range;
					tempBProof.status = Valid;
					BpMap.insert(bpid, tempBProof);
					BCWASM_EMIT_EVENT(Notify, "操作成功", 1);
				}
				else
				{
					BCWASM_EMIT_EVENT(Notify, "重复的申请！", 0);
				}
			}
			else
			{
				BCWASM_EMIT_EVENT(Notify, "无权限操作此did", 0);
			}
		}

		const char *get_proof(const char *bpid) const
		{
			string arrStr = "";
			const BProof *bproof = BpMap.find(bpid);
			if (bproof == nullptr)
			{
			}
			else
			{
				arrStr += "{\"bpid\":\"" + bproof->bpid + "\",\"did\":\"" + bproof->did + "\",\"proof\":\"" + bproof->proof + "\",\"range\":\"" + bproof->range + "\",\"status\":\"" + to_string(bproof->status) + "\"}";
			}
			return arrStr.c_str();
		}

		const char *verify_proof(const char *proof) const
		{
			std::string ret;
			ret = bcwasm::bulletProofVerify(proof);
			return ret.c_str();
		}

		void update_proof(const char *bpid, const char *did, int status)
		{
			BProof *bproof = BpMap.find(bpid);
			if (ensurePermissionByDid(did))
			{
				if (bproof == nullptr)
				{
					BCWASM_EMIT_EVENT(Notify, "不存在此Proof", 0);
				}
				else
				{
					BProof tempBProof;
					tempBProof.bpid = bproof->bpid;
					tempBProof.did = bproof->did;
					tempBProof.proof = bproof->proof;
					tempBProof.range = bproof->range;
					if (status == 1)
					{
						tempBProof.status = Expired;
					}
					else if (status == 2)
					{
						tempBProof.status = Revoked;
					}
					else
					{
						tempBProof.status = Valid;
					}
					BpMap.update(bpid, tempBProof);
					BCWASM_EMIT_EVENT(Notify, "操作成功", 1);
				}
			}
			else
			{
				BCWASM_EMIT_EVENT(Notify, "无权限操作此did", 0);
			}
		}

		

	private:
		bcwasm::db::Map<bpMapName, string, BProof> BpMap;
	};
}

BCWASM_ABI(did::bullet_proof, create_proof);
BCWASM_ABI(did::bullet_proof, get_proof);
BCWASM_ABI(did::bullet_proof, verify_proof);
BCWASM_ABI(did::bullet_proof, update_proof);

