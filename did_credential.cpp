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

namespace did {

//enum ServiceType {
//	RealName, FingerPrint, Enterprise, Business, VIP
//};
enum Status {
	UnRegistered, Registered
};
//证书状态
enum PendingStatus {
	NotProcessed, Processed, GenisisStatus
};

struct Issuer {
	string did;
	string website;
	string endpoint;
	string short_description;
	string long_description;
	string request_data;
			BCWASM_SERIALIZE(Issuer, (did)(website)(endpoint)(short_description)(long_description)(request_data))
	;
};
struct Credential {
	PendingStatus status; //证书状态
	string did; //申请者did
	string path; //证书路径
	BCWASM_SERIALIZE(Credential, (status)(did)(path))
	;
};
struct Pending {
	string did; //issuer did
	int service; //serviceType
	string serviceInfo;
	map<string, Credential> credentials_list; // key: userdid->serviceType
	BCWASM_SERIALIZE(Pending, (did)(service)(serviceInfo)(credentials_list))
	;
};

////发证方和服务
//struct IssuerAndService {
//	string did; //issuer did
//	int service;
//	bool operator <(const IssuerAndService &other) const {
//		if (strcmp(did.c_str(), other.did.c_str()) != 0) {
//			return true;
//		} else if (service < other.service) {
//			return true;
//		}
//		return false;
//	}
//	BCWASM_SERIALIZE(IssuerAndService, (did)(service))
//	;
//};

struct Request_Issuer {
	Issuer issuer;
	Status status;BCWASM_SERIALIZE(Request_Issuer, (issuer)(status))
	;
};

char issuerMapName[] = "IssuerMap";
char pendingMapName[] = "PendingMap";
char serivceMapName[] = "ServiceMap";
char credentialMapName[] = "CredentialMap";

class did_credential: public bcwasm::Contract {
public:
	did_credential() {
	}

	/// 实现父类: bcwasm::Contract 的虚函数
	/// 该函数在合约首次发布时执行，仅调用一次
	void init() {
		bcwasm::println("init  success...");
	}
	/// 定义Event.
	/// BCWASM_EVENT(eventName, arguments...)
	BCWASM_EVENT(Notify, const char *,int)

public:

	bool ensurePermissionByDid(const char *did) const {
		bcwasm::DeployedContract identityContract(
				"0x6FB6263c58Ed4cf8FB20A773233fC6DB41c77dE3");
		int64_t res = identityContract.callInt64("ensurePermissionByDid", did);
		return res == 1;
	}

	void request_to_be_issuer(const char *did, const char *issuerJson) {
		Request_Issuer *reqIssuer = IssuerMap.find(did);
		Issuer issuer;
		if (ensurePermissionByDid(did)) {
			if (deserializeIssuer(issuerJson, issuer)) {
				if (reqIssuer == nullptr) {
					Request_Issuer tempIssuer;
					tempIssuer.issuer = issuer;
					tempIssuer.status = UnRegistered;
					IssuerMap.insert(did, tempIssuer);
					BCWASM_EMIT_EVENT(Notify, "操作成功", 1);
				} else {
					BCWASM_EMIT_EVENT(Notify, "重复的申请！", 0);
				}
			} else {
				BCWASM_EMIT_EVENT(Notify, "解析issuer json失败！", 0);
			}
		} else {
			BCWASM_EMIT_EVENT(Notify, "无权限操作此did", 0);
		}
	}

	void approve_issuer(const char *did) {
		Request_Issuer *reqIssuer = IssuerMap.find(did);
		if (isAdmin()) {
			if (reqIssuer == nullptr) {
				BCWASM_EMIT_EVENT(Notify, "此DID无申请！", 0);
			} else {
				Request_Issuer tempIssuer;
				tempIssuer.issuer = reqIssuer->issuer;
				tempIssuer.status = Registered;
				IssuerMap.update(did, tempIssuer);
				BCWASM_EMIT_EVENT(Notify, "操作成功.", 1);
			}
		} else {
			BCWASM_EMIT_EVENT(Notify, "无权限操作", 0);
		}
	}

	void delete_issuer(const char *did) {
		Request_Issuer *reqIssuer = IssuerMap.find(did);
		if (isAdmin()) {
			if (reqIssuer == nullptr) {
				BCWASM_EMIT_EVENT(Notify, "此DID无申请！", 0);
			} else {
				IssuerMap.del(did);
				BCWASM_EMIT_EVENT(Notify, "操作成功", 1);
			}
		} else {
			BCWASM_EMIT_EVENT(Notify, "无权限操作", 0);
		}
	}

	void request_credential(const char *issuer_did, const char *self_did,
			int serviceType, const char *path) {
		if (ensurePermissionByDid(self_did)) {
			const Request_Issuer *issuer = IssuerMap.find(issuer_did);
			if (issuer == nullptr) {
				BCWASM_EMIT_EVENT(Notify, "issuer不存在！", 0);
			} else {
				Pending *pending = PendingMap.find(
						string(issuer_did) + "->" + to_string(serviceType));
				if (pending == nullptr) {
					BCWASM_EMIT_EVENT(Notify, "service不存在！", 0);
				} else {
					map<string, Credential>::iterator itr =
							pending->credentials_list.find(
									string(self_did) + "->"
											+ to_string(serviceType));
					if (itr == pending->credentials_list.end() || itr->second.status == GenisisStatus) {
						Credential temp;
						temp.did = self_did;
						temp.path = path;
						temp.status = NotProcessed;

						Pending tempPending;
						tempPending.credentials_list =
								pending->credentials_list;
						tempPending.did = pending->did;
						tempPending.service = pending->service;
						tempPending.serviceInfo = pending->serviceInfo;
						tempPending.credentials_list.insert(
								map<string, Credential>::value_type(
										string(self_did) + "->"
												+ to_string(serviceType),
										temp));
						PendingMap.update(
								string(issuer_did) + "->"
										+ to_string(serviceType), tempPending);
						BCWASM_EMIT_EVENT(Notify, "申请成功！", 1);
					} else {
						BCWASM_EMIT_EVENT(Notify, "重复申请！", 0);
					}
				}
			}
		} else {
			BCWASM_EMIT_EVENT(Notify, "无权限对此DID操作", 0);
		}
	}

	void approve_credential(const char *issuer_did, const char *self_did,
			int serviceType, const char *path) {
		if (ensurePermissionByDid(issuer_did)) {
			const Request_Issuer *issuer = IssuerMap.find(issuer_did);
			if (issuer == nullptr) {
				BCWASM_EMIT_EVENT(Notify, "issuer不存在！", 0);
			} else {
				Pending *pending = PendingMap.find(
						string(issuer_did) + "->" + to_string(serviceType));
				if (pending == nullptr) {
					BCWASM_EMIT_EVENT(Notify, "service不存在！", 0);
				} else {
					map<string, Credential>::iterator itr =
							pending->credentials_list.find(
									string(self_did) + "->"
											+ to_string(serviceType));
					if (itr == pending->credentials_list.end()) {
						BCWASM_EMIT_EVENT(Notify, "无申请！", 0);
					} else {
						Credential temp;
						temp.did = self_did;
						temp.path = path;
						temp.status = Processed;

						Pending tempPending;
						tempPending.credentials_list =
								pending->credentials_list;
						tempPending.did = pending->did;
						tempPending.service = pending->service;
						tempPending.serviceInfo = pending->serviceInfo;
						tempPending.credentials_list[string(self_did) + "->"
								+ to_string(serviceType)] = temp;
						PendingMap.update(
								string(issuer_did) + "->"
										+ to_string(serviceType), tempPending);
						BCWASM_EMIT_EVENT(Notify, "操作成功！", 1);
					}
				}
			}
		} else {
			BCWASM_EMIT_EVENT(Notify, "无权限对此DID操作", 0);
		}
	}

	void burn_credential(const char *issuer_did, const char *self_did,
			int serviceType, const char *path) {
		if (ensurePermissionByDid(issuer_did)) {
			const Request_Issuer *issuer = IssuerMap.find(issuer_did);
			if (issuer == nullptr) {
				BCWASM_EMIT_EVENT(Notify, "issuer不存在！", 0);
			} else {
				Pending *pending = PendingMap.find(
						string(issuer_did) + "->" + to_string(serviceType));
				if (pending == nullptr) {
					BCWASM_EMIT_EVENT(Notify, "service不存在！", 0);
				} else {
					map<string, Credential>::iterator itr =
							pending->credentials_list.find(
									string(self_did) + "->"
											+ to_string(serviceType));
					if (itr == pending->credentials_list.end()) {
						BCWASM_EMIT_EVENT(Notify, "无申请！", 0);
					} else {
						Credential temp;
						temp.did = self_did;
						temp.path = path;
						temp.status = GenisisStatus;

						Pending tempPending;
						tempPending.credentials_list =
								pending->credentials_list;
						tempPending.did = pending->did;
						tempPending.service = pending->service;
						tempPending.serviceInfo = pending->serviceInfo;
						tempPending.credentials_list[string(self_did) + "->"
								+ to_string(serviceType)] = temp;
						PendingMap.update(
								string(issuer_did) + "->"
										+ to_string(serviceType), tempPending);
						BCWASM_EMIT_EVENT(Notify, "操作成功！", 1);
					}
				}
			}
		} else {
			BCWASM_EMIT_EVENT(Notify, "无权限对此DID操作", 0);
		}
	}

	void start_specific_service(const char *issuer_did, int serviceType,
			const char *service_info) {
		if (ensurePermissionByDid(issuer_did)) {
			const Request_Issuer *issuer = IssuerMap.find(issuer_did);
			if (issuer == nullptr) {
				BCWASM_EMIT_EVENT(Notify, "issuer不存在！", 0);
			} else if (issuer->status == Registered) {
				Pending *pending = PendingMap.find(
						string(issuer_did) + "->" + to_string(serviceType));
				if (pending == nullptr) {
					Pending tempPending;
					tempPending.did = issuer_did;
					tempPending.service = serviceType;
					tempPending.serviceInfo = service_info;
					PendingMap.insert(
							string(issuer_did) + "->" + to_string(serviceType),
							tempPending);
//					map<int, string> *services = ServiceMap.find(issuer_did);
//					map<int, string> tempMap;
//					tempMap.insert(
//							map<int, string>::value_type(serviceType,
//									service_info));
//					if (services == nullptr) {
//						ServiceMap.update(issuer_did, tempMap);
//					} else {
//						ServiceMap.insert(issuer_did, tempMap);
//					}
					BCWASM_EMIT_EVENT(Notify, "操作成功", 1);
				} else {
					BCWASM_EMIT_EVENT(Notify, "service已经存在", 0);
				}
			} else {
				BCWASM_EMIT_EVENT(Notify, "无权限操作", 0);
			}
		} else {
			BCWASM_EMIT_EVENT(Notify, "无权限对此DID操作", 0);
		}
	}

	void stop_specific_service(const char *issuer_did, int serviceType) {
		if (ensurePermissionByDid(issuer_did)) {
			const Request_Issuer *issuer = IssuerMap.find(issuer_did);
			if (issuer == nullptr) {
				BCWASM_EMIT_EVENT(Notify, "issuer不存在！", 0);
			} else {
				Pending *pending = PendingMap.find(
						string(issuer_did) + "->" + to_string(serviceType));
				if (pending == nullptr) {
					BCWASM_EMIT_EVENT(Notify, "service不存在", 0);
				} else {
					PendingMap.del(
							string(issuer_did) + "->" + to_string(serviceType));
//					map<int, string> *issuerService = ServiceMap.find(
//							issuer_did);
//					if (issuerService == nullptr) {
//						BCWASM_EMIT_EVENT(Notify, "未找到描述");
//					} else {
//						issuerService->erase(serviceType);
//						ServiceMap.update(issuer_did, *issuerService);
//						BCWASM_EMIT_EVENT(Notify, "操作成功");
//					}
					BCWASM_EMIT_EVENT(Notify, "操作成功", 1);
				}
			}
		} else {
			BCWASM_EMIT_EVENT(Notify, "无权限对此DID操作", 0);
		}
	}

	const char* get_credential_list_by_did(const char *user_did) const {
		string arrStr = "";
		for (auto itr = PendingMap.begin(); itr != PendingMap.end(); itr++) {
			for (auto credentialListItr =
					itr->second().credentials_list.cbegin();
					credentialListItr != itr->second().credentials_list.cend();
					credentialListItr++) {
				if (credentialListItr->second.did == string(user_did)) {
					arrStr += "{\"issuer\":\"" + itr->second().did
							+ "\",\"serviceType\":\"" + to_string(itr->second().service)
							+ "\",\"serviceInfo\":\""
							+ itr->second().serviceInfo + "\",\"path\":\""
							+ credentialListItr->second.path
							+ "\",\"status\":\""
							+ to_string(credentialListItr->second.status)
							+ "\"},";
				}
			}
		}
		string res = "{\"credentialList\":["
				+ arrStr.substr(0, arrStr.length() - 1) + "]}";
		return res.c_str();
	}

	const char* get_request_credential_list_by_issuerid(
			const char *issuer_did) const {
		string arrStr = "";
		for (auto itr = PendingMap.begin(); itr != PendingMap.end(); itr++) {
			if (itr->second().did == string(issuer_did)) {
				auto credentialMap = itr->second().credentials_list;
				for (auto credentialMapItr = credentialMap.cbegin();
						credentialMapItr != credentialMap.cend();
						credentialMapItr++) {
					arrStr += "{\"userSta\":\"" + credentialMapItr->second.did
							+ "\",\"serviceType\":\"" + to_string(itr->second().service)
							+ "\",\"serviceInfo\":\""
							+ itr->second().serviceInfo + "\",\"path\":\""
							+ credentialMapItr->second.path
							+ "\",\"status\":\""
							+ to_string(credentialMapItr->second.status)
							+ "\"},";
				}
			}

		}
		string res = "{\"requestCredentialList\":["
				+ arrStr.substr(0, arrStr.length() - 1) + "]}";
		return res.c_str();
	}

	const char* get_servicelist_by_did(const char *issuer_did) const {
//		map<int, string> *service = ServiceMap.find(issuer_did);
//		if (service == nullptr) {
//			return string("{\"serviceList\":[]}").c_str();
//		} else {
//			string arrStr = "";
//			//{"serviceType":"","serviceInfo":""}
//			for (int i = 0; i < service->size(); i++) {
//				arrStr += "{\"serviceType\":\"" + to_string(i)
//						+ "+\",\"serviceInfo\":\"" + service->at(i) + "\"},";
//			}
//			if (service->size() > 0) {
//				arrStr = arrStr.substr(0, arrStr.length() - 1);
//			}
//			arrStr = "{\"serviceList\":[" + arrStr + "]}";
//			return arrStr.c_str();
//		}
		string arrStr = "";
		for (auto itr = PendingMap.cbegin(); itr != PendingMap.cend(); itr++) {
			if (itr->second().did == string(issuer_did)) {
				string key = itr->first();
				string info = itr->second().serviceInfo;
				arrStr += "{\"key\":\"" + key + "\",\"info\":\"" + info
						+ "\"},";
			}
		}

		string res = "{\"servicelist\":["
				+ arrStr.substr(0, arrStr.length() - 1) + "]}";
		return res.c_str();
	}

	const char* get_issuer_list() const {
		string arrStr = "";
		for (auto itr = IssuerMap.cbegin(); itr != IssuerMap.cend(); itr++) {
			arrStr += "{\"issuer\":{\"did\":\"" + itr->second().issuer.did
					+ "\",\"website\":\"" + itr->second().issuer.website
					+ "\",\"endpoint\":\"" + itr->second().issuer.endpoint
					+ "\",\"short_description\":\""
					+ itr->second().issuer.short_description
					+ "\",\"long_description\":\""
					+ itr->second().issuer.long_description
					+ "\",\"request_data\":\""
					+ itr->second().issuer.request_data + "\"},\"status\":\""
					+ to_string(itr->second().status) + "\"},";
			bcwasm::println(arrStr);
		}

		string res = "{\"issuerList\":[" + arrStr.substr(0, arrStr.length() - 1)
				+ "]}";
		return res.c_str();
	}

	const char* get_issuer_by_did(const char *issuer_did) const {
		const Request_Issuer *req_issuer = IssuerMap.find(issuer_did);
		string res = "{\"issuer\":{\"did\":\"" + req_issuer->issuer.did
				+ "\",\"website\":\"" + req_issuer->issuer.website
				+ "\",\"endpoint\":\"" + req_issuer->issuer.endpoint
				+ "\",\"short_description\":\""
				+ req_issuer->issuer.short_description
				+ "\",\"long_description\":\""
				+ req_issuer->issuer.long_description + "\",\"request_data\":\""
				+ req_issuer->issuer.request_data + "\"},\"status\":\""
				+ to_string(req_issuer->status) + "\"}";
		return res.c_str();

	}

	void set_credential(const char *path, const char *credentialContent) {
		string *credential = CredentialMap.find(path);
		if (credential == nullptr) {
			CredentialMap.insert(path, credentialContent);
			BCWASM_EMIT_EVENT(Notify, "插入成功", 1);
		} else {
			BCWASM_EMIT_EVENT(Notify, "path已存在", 0);
		}
	}
	
    void update_credential(const char *path, const char *credentialContent) {
		string *credential = CredentialMap.find(path);
		if (credential == nullptr) {
			BCWASM_EMIT_EVENT(Notify, "凭证不存在", 0);
		} else {
			CredentialMap.update(path, credentialContent);
			BCWASM_EMIT_EVENT(Notify, "插入成功", 1);
		}
	}
	
	const char* get_credential(const char *path) const {
		const string *credential = CredentialMap.find(path);
		string arrStr = "";
		if (credential == nullptr) {
		      arrStr = "{\"error\":\"path不存在\"}";
		} else {
		      arrStr = "{\"credential\":\""+ *credential +"\"}";
		}
		return arrStr.c_str();
	}

	bool isAdmin() const {
		return true;
	}

//反序列化DidProof
	bool deserializeIssuer(const std::string &issuerJson,
			Issuer &issuer) const {
		Document doc;
		doc.Parse<kParseDefaultFlags>(issuerJson.c_str());
		Document::AllocatorType &allocator = doc.GetAllocator();
		if (doc.HasParseError()) {
			ParseErrorCode code = doc.GetParseError();
			bcwasm::println("解析issuerJson失败，错误码：", code);
			return false;
		}

		Value::MemberIterator itr = doc.FindMember("did");
		if (itr == doc.MemberEnd()) {
			bcwasm::println("没找到对应的did");
		} else {
			issuer.did = itr->value.GetString();
		}

		itr = doc.FindMember("endpoint");
		if (itr == doc.MemberEnd()) {
			bcwasm::println("没找到对应的 endpoint");
		} else {
			issuer.endpoint = itr->value.GetString();
		}

		itr = doc.FindMember("long_description");
		if (itr == doc.MemberEnd()) {
			bcwasm::println("没找到对应的 long_description");
		} else {
			issuer.long_description = itr->value.GetString();
		}
		itr = doc.FindMember("short_description");
		if (itr == doc.MemberEnd()) {
			bcwasm::println("没找到对应的 short_description ");
		} else {
			issuer.short_description = itr->value.GetString();
		}
		itr = doc.FindMember("request_data");
		if (itr == doc.MemberEnd()) {
			bcwasm::println("没找到对应的  request_data");
		} else {
			issuer.request_data = itr->value.GetString();
		}
		itr = doc.FindMember("website");
		if (itr == doc.MemberEnd()) {
			bcwasm::println("没找到对应的 website");
		} else {
			issuer.website = itr->value.GetString();
		}

		return true;
	}

private:

	bcwasm::db::Map<issuerMapName, string, Request_Issuer> IssuerMap;

	bcwasm::db::Map<pendingMapName, string, Pending> PendingMap; //key: "did->serviceType"

	bcwasm::db::Map<serivceMapName, int, string> ServiceMap; //key: "did" value:map<serviceType,info>

	bcwasm::db::Map<credentialMapName, string, string> CredentialMap; //@param path  @param 明文/密文hash
};
}

BCWASM_ABI(did::did_credential, request_to_be_issuer);
BCWASM_ABI(did::did_credential, approve_issuer);
BCWASM_ABI(did::did_credential, delete_issuer);
BCWASM_ABI(did::did_credential, request_credential);
BCWASM_ABI(did::did_credential, approve_credential);
BCWASM_ABI(did::did_credential, burn_credential);
BCWASM_ABI(did::did_credential, start_specific_service);
BCWASM_ABI(did::did_credential, stop_specific_service);
BCWASM_ABI(did::did_credential, get_request_credential_list_by_issuerid);
BCWASM_ABI(did::did_credential, get_credential_list_by_did);
BCWASM_ABI(did::did_credential, get_servicelist_by_did);
BCWASM_ABI(did::did_credential, get_issuer_list);
BCWASM_ABI(did::did_credential, get_issuer_by_did);
BCWASM_ABI(did::did_credential, set_credential);
BCWASM_ABI(did::did_credential, update_credential);
BCWASM_ABI(did::did_credential, get_credential);


