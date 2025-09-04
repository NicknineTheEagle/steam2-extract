#pragma once
#include <cryptopp/aes.h>
#include <filesystem>
#include <fstream>
#include <istream>
#include <map>
#include <mutex>
#include <string>
#include <vector>

#ifdef STEAM2_BUILD_NET
#include <asio.hpp>
#endif

namespace steam2 {
	namespace util {
		class KeyStore {
		public:
			KeyStore();

			void PopulateFromJSON();
			void PopulateFromVDF();

			inline bool has_key(uint32_t depot) {
				return m_keys.contains(depot);
			}

			inline std::string get(uint32_t depot) {
				return m_keys[depot];
			}

			std::map<uint32_t, std::string> m_keys;
		};
	}

	class Manifest {
	private:
		struct DirectoryEntry {
			uint32_t nameoffset;
			uint32_t itemsize;
			uint32_t fileid;
			uint32_t dirtype;
			uint32_t parentindex;
			uint32_t nextindex;
			uint32_t firstindex;
		};

	public:
		Manifest(std::string file_path);
		Manifest(std::istream& read);
		~Manifest();

		void parse_stream(std::istream& read);

		std::filesystem::path full_path_for_entry(const DirectoryEntry& entry);

		inline std::filesystem::path full_path_for_entry(int index) {
			return full_path_for_entry(m_direntries[index]);
		}

		struct Header {
			uint32_t dummy1;
			uint32_t cacheid;
			uint32_t gcfversion;
			uint32_t itemcount;
			uint32_t filecount;
			uint32_t blocksize;
			uint32_t dirsize;
			uint32_t namesize;
			uint32_t info1count;
			uint32_t copycount;
			uint32_t localcount;
			uint32_t dummy3;
			uint32_t dummy4;
			uint32_t checksum;
		} m_header{};

		std::string strtable;
		std::vector<DirectoryEntry> m_direntries;
		std::map<uint32_t, std::string> m_stringtable;
		std::vector<uint32_t> m_copyentries;
	//public:
		//std::streamsize m_stringtable{};
		//std::ifstream m_file;
	};

	// this fucking format makes me wanna wish merry christmas
	class Index {
	public:
		enum version {
			v2,
			v3
		};

		Index(std::string file_path, version ver = version::v3);
		~Index();

		enum filetype {
			raw = 0,
			compressed,
			compressed_and_crypted,
			crypted
		};
		
		struct inode {
			struct chunk {
				uint64_t start;
				uint64_t length;
			};

			filetype m_type;
			std::vector<chunk> m_chunks;
		};

		static std::string filetype_to_string(filetype f);

		//typedef std::map < uint64_t, std::vector<std::pair<uint64_t, uint64_t>>> index_t;
		//std::map < uint64_t, filetype> modes;
		//index_t indexes;

		std::map<uint64_t, inode> m_indexes;
	private:
		void load_v3(uintmax_t size);
		void load_v2(uintmax_t size);
		std::ifstream m_file;
	};

	class Storage {
	public:
		Storage(std::string file_path, std::string hex_key);
		static void handle_chunk(std::ostream& out, Index::filetype type, std::istream& input, size_t len, std::string key);
		void extract_file(std::ostream& out, steam2::Index& index, uint32_t fileid);

		bool m_encrypted = false;
		CryptoPP::byte m_key[16] = { 0 };
		CryptoPP::byte m_iv[16] = { 0 };
	private:
		std::mutex m_io_lock;
		std::ifstream m_file;
	};

	class Checksum {
	public:
		static uint32_t hashblock(char* block, size_t count);	

		Checksum(std::string file);
		Checksum(std::istream& s);
		int num_checksums(std::uint32_t fileid);

		struct hdr_t {
			uint32_t dummy1;
			uint32_t dummy2;
			uint32_t items;
			uint32_t checksums;
		} m_header;

		struct mapnode_t {
			uint32_t count;
			uint32_t firstidx;
		};

		struct entry_t {
			uint32_t sum;
		};

		std::vector<entry_t> m_entries;
		std::vector<mapnode_t> m_map;
	};
#ifdef STEAM2_BUILD_NET
	namespace net {
		struct addr {
			asio::ip::address ip;
			unsigned short port;
		};

		class FileClient {
		public:
			struct fc_chunk {
				char* buf;
				size_t size;
			};

			FileClient(net::addr addr, unsigned appid, unsigned version);

			Index::filetype get_chunks(int fileid, int filestart, int numchunks, std::vector<std::string>& chunks);
			std::vector<std::string> get_file(unsigned fileid, int totalchunks, Index::filetype& mode);
			std::string get_metadata(int cmd);
			Manifest download_manifest();
			Checksum download_checksums();
			void enter_storage();
			void connect();
			void connect_and_open();
			void open_storage();
			std::string receive_data_withlen();
			std::string recv_part_data(size_t len);
			std::string recv_message(size_t len);
			std::string send_command(int cmd, char* extra = nullptr, size_t len = 0);
		private:
			bool m_connected = false;
			unsigned m_storageid = 0;
			unsigned m_msgid = 0;
			addr m_address;
			unsigned m_appid = 0;
			unsigned m_version = 0;
			unsigned m_retries = 5;
			asio::io_context io_context;
			asio::ip::tcp::socket s;
		};

#pragma pack(push, 1)

		struct pkt_cmforapp {
			uint32_t size = 419430400;
			uint8_t pad = 0;
			uint16_t pkt_type = 256;
			uint32_t app = 0;
			uint32_t version = 0;
			uint16_t max_servers = 0;
			uint32_t unk = 83886080;
			uint64_t unk2 = 0xFFFFFFFFFFFFFFFF;
		};
#pragma pack(pop)
		std::vector<addr> get_fileservers(addr cls, unsigned app, unsigned version, short max);
		bool download_cdr(addr cdr_addr, std::ostream& s);
	}
#endif
}