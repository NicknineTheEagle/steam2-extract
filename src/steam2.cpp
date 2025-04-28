#include <cryptopp/aes.h>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>
#include <cryptopp/modes.h>
#include <fstream>
#include <iostream>
#include <print>
#include <zlib.h>

#include "json.hpp"
#include "steam2.hpp"
#include "vdf_parser.hpp"

using namespace steam2;

Manifest::Manifest(std::string file_path) {
	std::ifstream m_file = std::ifstream(file_path, std::ios_base::binary);
	if (!m_file.good())
		throw std::runtime_error("Invalid manifest path!");

	parse_stream(m_file);
	// read header
	/*file.read(reinterpret_cast<char*>(&m_header), sizeof(m_header));

	//read directory entries
	m_direntries.resize(m_header.itemcount);
	m_file.read(reinterpret_cast<char*>(m_direntries.data()), m_header.itemcount * sizeof(DirectoryEntry));
	std::streamsize start_stringtable = m_file.tellg();
	for (auto const& e : m_direntries) {

		std::getline()

		m_stringtable[e.fileid] = std::get
		e.nameoffset
	}*/
}

Manifest::Manifest(std::istream& s) {
	parse_stream(s);
}

void Manifest::parse_stream(std::istream &s) {
	// read header
	s.read(reinterpret_cast<char*>(&m_header), sizeof(m_header));

	//read directory entries
	m_direntries.resize(m_header.itemcount);
	s.read(reinterpret_cast<char*>(m_direntries.data()), m_header.itemcount * sizeof(DirectoryEntry));
	std::streamsize start_stringtable = s.tellg();
	int i = 0;
	for (auto const& e : m_direntries) {
		if (e.nameoffset == 0xFFFFFFFF) continue;
		s.seekg(start_stringtable + e.nameoffset, std::ios::beg);
		std::string current;
		std::getline(s, current, '\0');
		m_stringtable[i] = current;
		i++;
	}
}

Manifest::~Manifest() {
	//m_file.close();
}

std::filesystem::path Manifest::full_path_for_entry(const DirectoryEntry& entry) {
	//if (!m_file.good()) {
		/*DirectoryEntry cur_entry = entry;
		std::string path;
		std::stringstream ss(strtable, std::ios_base::binary);
		while (cur_entry.parentindex != 0xFFFFFFFF) {
			ss.seekg(m_stringtable + cur_entry.nameoffset, std::ios::beg);
			std::string part;
			std::getline(ss, part, '\0');
			path.insert(0, part);
			if (cur_entry.parentindex != 0) {
				path.insert(0, "/");
			}
			cur_entry = m_direntries[cur_entry.parentindex];
		}
		return path;*/
	//}
	/*std::streamsize tell = m_file.tellg();
	DirectoryEntry cur_entry = entry;
	std::string path;
	while (cur_entry.parentindex != 0xFFFFFFFF) {
		m_file.seekg(m_stringtable + cur_entry.nameoffset, std::ios::beg);
		std::string part;
		std::getline(m_file, part, '\0');
		path.insert(0, part);
		if (cur_entry.parentindex != 0) {
			path.insert(0, "/");
		}
		cur_entry = m_direntries[cur_entry.parentindex];
	}
	m_file.seekg(tell, std::ios::beg);
	return path;*/

	auto find = [this](const DirectoryEntry& a){
		uint32_t i = 0;
		for (auto const& cur : m_direntries) {
			if (a.nameoffset == cur.nameoffset && a.parentindex == cur.parentindex) {
				return i;
			}
			i++;
		}
		return 0xFFFFFFFF;
	};
	std::string path;
	// 
	//reinterpret_cast<DirectoryEntry*>(entry) - 

	uint32_t idx = find(entry);
	DirectoryEntry cur_entry = entry;
	while (cur_entry.parentindex != 0xFFFFFFFF) {
		path.insert(0, m_stringtable[idx]);
		if (cur_entry.parentindex != 0) {
			path.insert(0, "/");
		}
		idx = cur_entry.parentindex;
		cur_entry = m_direntries[cur_entry.parentindex];
	}
	return path;
}

// rewrite
void Index::load_v3(uintmax_t size) {

	while (m_file.tellg() < static_cast<std::streampos>(size)) {
		struct Part {
			uint64_t fileid;
			uint64_t length;
			uint64_t mode;
		} p;

		m_file.read(reinterpret_cast<char*>(&p), sizeof(Part));
		p.fileid = std::byteswap<uint64_t>(p.fileid);
		p.length = std::byteswap<uint64_t>(p.length);
		p.mode = std::byteswap<uint64_t>(p.mode);

		if (p.mode > 3 || p.length > size)
			throw std::runtime_error("bad index");

		m_indexes[p.fileid] = {};

		if (p.length) {
			m_indexes[p.fileid].m_type = static_cast<filetype>(p.mode);
			//indexes[p.fileid] = {};
			while (p.length != 0) {
				struct u64pair {
					uint64_t start;
					uint64_t length;
				} pair;
				m_file.read(reinterpret_cast<char*>(&pair), sizeof(pair));

				auto& chunk = m_indexes[p.fileid].m_chunks.emplace_back();
				chunk.start = std::byteswap<uint64_t>(pair.start);
				chunk.length = std::byteswap<uint64_t>(pair.length);
				//indexes[p.fileid].push_back({ std::byteswap<uint64_t>(pair.start), std::byteswap<uint64_t>(pair.length) });
				p.length -= sizeof(u64pair);
			}
		}
	}
}

void Index::load_v2(uintmax_t size) {

	while (m_file.tellg() < static_cast<std::streampos>(size)) {
		struct Part {
			uint32_t fileid;
			uint32_t length;
			uint32_t mode;
		} p;

		m_file.read(reinterpret_cast<char*>(&p), sizeof(Part));
		p.fileid = std::byteswap<uint32_t>(p.fileid);
		p.length = std::byteswap<uint32_t>(p.length);
		p.mode = std::byteswap<uint32_t>(p.mode);

		if (p.mode > 3 || p.length > size)
			throw std::runtime_error("bad index");

		m_indexes[p.fileid] = {};

		if (p.length) {
			m_indexes[p.fileid].m_type = static_cast<filetype>(p.mode);
			//indexes[p.fileid] = {};
			while (p.length != 0) {
				struct u64pair {
					uint32_t start;
					uint32_t length;
				} pair;
				m_file.read(reinterpret_cast<char*>(&pair), sizeof(pair));

				auto& chunk = m_indexes[p.fileid].m_chunks.emplace_back();
				chunk.start = std::byteswap<uint32_t>(pair.start);
				chunk.length = std::byteswap<uint32_t>(pair.length);
				//indexes[p.fileid].push_back({ std::byteswap<uint64_t>(pair.start), std::byteswap<uint64_t>(pair.length) });
				p.length -= sizeof(u64pair);
			}
		}
	}
}

Index::Index(std::string file_path, version ver) {
	m_file = std::ifstream(file_path, std::ios_base::binary);
	if (!m_file.good())
		throw std::runtime_error("Invalid index path!");

	auto size = std::filesystem::file_size(file_path);

	switch (ver) {
	case version::v2:
		load_v2(size);
		break;
	case version::v3:
		load_v3(size);
		break;
	}
}

Index::~Index() {
	m_file.close();
}

Storage::Storage(std::string file_path, std::string hex_key) {
	m_file = std::ifstream(file_path, std::ios_base::binary);
	if (!m_file.good())
		throw std::runtime_error("Invalid storage path");

	if (hex_key == "00000000000000000000000000000000") {
		m_encrypted = false;
	} else {
		CryptoPP::HexDecoder decoder;
		decoder.Put(reinterpret_cast<CryptoPP::byte*>(hex_key.data()), hex_key.size());
		decoder.MessageEnd();
		decoder.Get(m_key, sizeof(m_key));
		m_encrypted = true;
	}
}

void Storage::extract_file(std::ostream& out, Index& index, uint32_t fileid) {
	thread_local static char decryptbuf[0x8000];

	for (const auto& pair : index.m_indexes[fileid].m_chunks) {
		if (pair.length == 0) continue;
		auto& filetype = index.m_indexes[fileid].m_type;
		std::vector<char> chunk;
		chunk.resize(pair.length);
		m_io_lock.lock();
		m_file.seekg(pair.start);
		m_file.read(chunk.data(), chunk.size());
		m_io_lock.unlock();

		switch (filetype) {
		case Index::filetype::raw:
			out.write(chunk.data(), chunk.size());
			break;
		case Index::filetype::compressed: {
			//char* dbuf = new char[32768];
			uLongf dstlen = 32768;
			int res = uncompress(reinterpret_cast<unsigned char*>(decryptbuf), &dstlen, reinterpret_cast<Bytef*>(chunk.data()), static_cast<uLong>(chunk.size()));
			if (res) {
				throw std::runtime_error("Failed! (compressed)");
			}
			out.write(decryptbuf, dstlen);
			//delete[] dbuf;
			break;
		}
		case Index::filetype::compressed_and_crypted: {
			if (!m_encrypted) {
				throw std::runtime_error("depot encrypted, no key provided! aborting!");
			}
			struct encparams_t {
				uint32_t encsize;
				uint32_t decsize;
			};
			encparams_t params = *reinterpret_cast<encparams_t*>(chunk.data());
			if ((chunk.size() - 0x8) % 0x10 != 0) {
				size_t to_insert = 0x10 - ((chunk.size() - 0x8) % 0x10);
				chunk.resize(chunk.size() + to_insert, '\0');
			}
			// decrypt
			CryptoPP::CFB_Mode< CryptoPP::AES >::Decryption d;
			d.SetKeyWithIV(m_key, sizeof(m_key), m_iv, sizeof(m_iv));

			std::vector<CryptoPP::byte> decbuf;
			CryptoPP::StringSource source(reinterpret_cast<CryptoPP::byte*>(chunk.data() + 0x8), chunk.size() - 0x8, true, new CryptoPP::StreamTransformationFilter(d, new CryptoPP::VectorSink(decbuf)));

			// decompress
			//std::println(std::cout, "size {}", params.decsize);
			//Bytef* uncbuf = new Bytef[params.decsize];
			uLongf dstlen = params.decsize;
			int res = uncompress(reinterpret_cast<Bytef*>(decryptbuf), &dstlen, reinterpret_cast<Bytef*>(decbuf.data()), static_cast<uLong>(decbuf.size()));
			if (res) {
				throw std::runtime_error("Failed! (crypted and compressed)");
			}
			out.write(decryptbuf, dstlen);
			//delete[] uncbuf;
			break;
		}
		case Index::filetype::crypted: {
			if (!m_encrypted) {
				throw std::runtime_error("depot encrypted, no key provided! aborting!");
			}
			if (chunk.size() % 10 != 0) {
				chunk.resize(chunk.size() + (0x10 - (chunk.size() % 10)), '\0');
			}

			//decrypt
			CryptoPP::CFB_Mode< CryptoPP::AES >::Decryption d;
			d.SetKeyWithIV(m_key, sizeof(m_key), m_iv, sizeof(m_iv));

			std::vector<CryptoPP::byte> decbuf;

			CryptoPP::StringSource source(reinterpret_cast<CryptoPP::byte*>(chunk.data()), chunk.size(), true, new CryptoPP::StreamTransformationFilter(d, new CryptoPP::VectorSink(decbuf)));
			out.write(reinterpret_cast<char*>(decbuf.data()), pair.length);
			break;
		}
		}
	}
}


void Storage::handle_chunk(std::ostream& out, Index::filetype type, std::istream& input, size_t len, std::string key) {
	bool keyset = false;
	CryptoPP::byte key_[16];
	CryptoPP::byte iv[16] = { 0 };
	if (key == "00000000000000000000000000000000") {
		keyset = false;
	}
	else {
		CryptoPP::HexDecoder decoder;
		decoder.Put(reinterpret_cast<CryptoPP::byte*>(key.data()), key.size());
		decoder.MessageEnd();
		decoder.Get(key_, sizeof(key_));
		keyset = true;
	}

	switch (type) {
		case Index::filetype::raw:
			out << input.rdbuf();
			break;
		case Index::filetype::compressed: {
			char* dbuf = new char[32768];
			uLongf dstlen = 32768;
			char* tmpbf = new char[len];

			input.read(tmpbf, len);
			int res = uncompress((Bytef*)dbuf, &dstlen, reinterpret_cast<Bytef*>(tmpbf), static_cast<uLong>(len));
			if (res) {
				throw std::runtime_error("Failed! (compressed)");
			}
			out.write(dbuf, dstlen);
			delete[] dbuf;
			delete[] tmpbf;
			break;
		}
		case Index::filetype::compressed_and_crypted: {
			std::vector<char> data;
			data.resize(len);
			input.read(data.data(), len);

			if (!keyset) {
				throw std::runtime_error("depot encrypted, no key provided! aborting!");
			}

			struct encparams_t {
				uint32_t encsize;
				uint32_t decsize;
			};

			encparams_t params = *reinterpret_cast<encparams_t*>(data.data());
			if ((len -0x8) % 0x10 != 0) {
				size_t to_insert = 0x10 - ((data.size() - 0x8) % 0x10);
				data.resize(data.size() + to_insert, '\0');
			}

			// decrypt
			CryptoPP::CFB_Mode< CryptoPP::AES >::Decryption d;
			d.SetKeyWithIV(key_, sizeof(key_), iv, sizeof(iv));

			std::vector<CryptoPP::byte> decbuf;
			CryptoPP::StringSource source(reinterpret_cast<CryptoPP::byte*>(data.data() + 0x8), data.size() - 0x8, true, new CryptoPP::StreamTransformationFilter(d, new CryptoPP::VectorSink(decbuf)));

			// decompress
			Bytef* uncbuf = new Bytef[params.decsize];
			uLongf dstlen = params.decsize;
			int res = uncompress(uncbuf, &dstlen, reinterpret_cast<Bytef*>(decbuf.data()), static_cast<uLong>(decbuf.size()));
			if (res) {
				throw std::runtime_error("Failed! (crypted and compressed)");
			}
			out.write(reinterpret_cast<char*>(uncbuf), dstlen);
			delete[] uncbuf;
			break;
		}
		case Index::filetype::crypted: {
			std::vector<char> data;
			data.resize(len);
			input.read(data.data(), len);

			if (!keyset) {
				throw std::runtime_error("depot encrypted, no key provided! aborting!");
			}

			if (data.size() % 10 != 0) {
				data.resize(data.size() + (0x10 - (data.size() % 10)), '\0');
			}

			//decrypt
			CryptoPP::CFB_Mode< CryptoPP::AES >::Decryption d;
			d.SetKeyWithIV(key_, sizeof(key_), iv, sizeof(iv));

			std::vector<CryptoPP::byte> decbuf;

			CryptoPP::StringSource source(reinterpret_cast<CryptoPP::byte*>(data.data()), data.size(), true, new CryptoPP::StreamTransformationFilter(d, new CryptoPP::VectorSink(decbuf)));
			out.write(reinterpret_cast<char*>(decbuf.data()), len);
			break;
		}
		}
}


Checksum::Checksum(std::string file) {
	std::ifstream f(file, std::ios_base::binary);
	if (!f.good())
		throw std::runtime_error("Invalid checksum path");

	f.read(reinterpret_cast<char*>(&m_header), sizeof(hdr_t));
	m_map.resize(m_header.items);
	f.read(reinterpret_cast<char*>(m_map.data()), sizeof(mapnode_t) * m_header.items);
	m_entries.resize(m_header.checksums);
	f.read(reinterpret_cast<char*>(m_entries.data()), sizeof(entry_t) * m_header.checksums);
}

Checksum::Checksum(std::istream& f) {

	f.read(reinterpret_cast<char*>(&m_header), sizeof(hdr_t));
	m_map.resize(m_header.items);
	f.read(reinterpret_cast<char*>(m_map.data()), sizeof(mapnode_t) * m_header.items);
	m_entries.resize(m_header.checksums);
	f.read(reinterpret_cast<char*>(m_entries.data()), sizeof(entry_t) * m_header.checksums);
}

int Checksum::num_checksums(uint32_t fileid) {
	return m_map[fileid].count;
}


uint32_t Checksum::hashblock(char* block, size_t size) {
	return crc32(0, reinterpret_cast<Bytef*>(block), static_cast<uInt>(size)) ^ adler32(0, reinterpret_cast<Bytef*>(block), static_cast<uInt>(size));
}

std::string Index::filetype_to_string(Index::filetype f) {
	switch (f) {
	case Index::filetype::compressed:
		return "compressed";
	case Index::filetype::compressed_and_crypted:
		return "compressed and encrypted";
	case Index::filetype::raw:
		return "raw";
	case Index::filetype::crypted:
		return "encrypted";
	}
	return "n/a";
}

void util::KeyStore::PopulateFromVDF() {
	std::ifstream f("legacydepotdata.vdf");
	auto root = tyti::vdf::read(f);
	for (auto& ref : root.attribs) {
		m_keys[std::stoi(ref.first)] = ref.second;
	}
}

void util::KeyStore::PopulateFromJSON() {
	std::ifstream f("depotkeys.json");
	nlohmann::json j;
	f >> j;
	auto& keys = j["keys"];
	for (auto it = keys.begin(); it != keys.end(); ++it) {
		m_keys[std::stoi(it.key())] = it.value();
	}
}

util::KeyStore::KeyStore() {
	if (std::filesystem::exists("legacydepotdata.vdf")) {
		PopulateFromVDF();
	} else if (std::filesystem::exists("depotkeys.json")) {
		PopulateFromJSON();
	}
}

// net
#ifdef STEAM2_BUILD_NET
using asio::ip::tcp;
std::string net::FileClient::receive_data_withlen() {
	uint32_t len = *reinterpret_cast<uint32_t*>(recv_message(4).data());
	len = std::byteswap(len);
	return recv_part_data(len);
}

std::string net::FileClient::recv_message(size_t len) {
	struct msgctx {
		uint32_t storageid;
		uint32_t mesasgeid;
	} msg;
	
	asio::read(s, asio::buffer(&msg, sizeof(msg)));

	if (m_storageid != std::byteswap(msg.storageid)) {
		throw std::runtime_error("bad storageid");
	}

	if (m_msgid != std::byteswap(msg.mesasgeid)) {
		throw std::runtime_error("bad storageid");
	}

	std::string str;
	str.resize(len);
	asio::read(s, asio::buffer(str.data(), str.length()));
	return str;
}


std::string net::FileClient::send_command(int cmd, char* extra, size_t len) {
	if (cmd == 9 or cmd == 10)
		m_storageid = 1;

#pragma pack(push, 1)
	struct cmd_t {
		uint32_t len;
		uint8_t cmdid;
		uint32_t storageid;
		uint32_t msgid;
	} cmdctx;
#pragma pack(pop)

	unsigned size = static_cast<unsigned>(sizeof(cmd_t)) - 4 + static_cast<unsigned>(len);
	cmdctx.len = std::byteswap(size);
	cmdctx.cmdid = static_cast<uint8_t>(cmd);
	cmdctx.storageid = std::byteswap(m_storageid);
	cmdctx.msgid = std::byteswap(m_msgid);

	s.send(asio::buffer(&cmdctx, sizeof(cmdctx)));
	if (extra) {
		s.send(asio::buffer(extra, len));
	}
	if (cmd == 9 || cmd == 10) {
		m_storageid = 0x80000001;
	}
	//delete[] tempbuffer;
	return recv_message(1);

}

void net::FileClient::open_storage() {
	struct av_t {
		uint32_t a;
		uint32_t v;
	} av;
	av.a = std::byteswap(m_appid);
	av.v = std::byteswap(m_version);

	auto str = send_command(9, reinterpret_cast<char*>(&av), sizeof(av));
	if (str.length() == 1 and *str.c_str() != '\0'){
		m_connected = false;
		throw std::runtime_error("cs refused");
	}

	struct sc_t {
		uint32_t s;
		uint32_t c;
	} sc;
	asio::read(s, asio::buffer(&sc, sizeof(sc)));
	m_storageid = std::byteswap(sc.s);
	m_connected = true;
}

void net::FileClient::enter_storage() {
	s.send(asio::buffer("\x00\x00\x00\x07", 4));
	char a;
	asio::read(s, asio::buffer(&a, 1));
	s.send(asio::buffer("\x00\x00\x00\x05\x00\x00\x00\x00\x05", 9));
	//char junk[16384];
#pragma pack(push, 1)
	struct fuckingbanner {
		uint8_t pad;
		uint16_t urllen;
	} fb; // DIE
#pragma pack(pop)
	asio::read(s, asio::buffer(&fb, sizeof(fuckingbanner)));
	size_t len = std::byteswap(fb.urllen);
	
	char* randomurl = new char[len];
	asio::read(s, asio::buffer(randomurl, len));
	delete[] randomurl;
}

void net::FileClient::connect() {
	s.connect(tcp::endpoint(m_address.ip, m_address.port));
}
void net::FileClient::connect_and_open() {
	connect();
	enter_storage();
	open_storage();
	m_connected = true;
}

std::string net::FileClient::recv_part_data(size_t len) {
	std::string str;

	while (str.length() < len) {
		std::string reply = recv_message(4);
		uint32_t partlen = std::byteswap(*reinterpret_cast<uint32_t*>(reply.data()));
		size_t boff = str.length();
		str.resize(str.length() + partlen);
		asio::read(s, asio::buffer(str.data() + boff, partlen));

	}
	return str;
}

net::FileClient::FileClient(net::addr addr, unsigned appid, unsigned version) : s(io_context) {
	m_address = addr;
	//s = tcp::socket(io_context);


	//tcp::socket s(io_context);
	m_appid = appid;
	m_version = version;
	unsigned retry_count = 0;
	while (retry_count < m_retries) {
		try {
			connect_and_open();
			break;
		} catch (std::exception& ex) {
			//std::cout << ex.what() << "\n";
			s.close();
			retry_count++;
		}
	}

	if (!m_connected) {
		throw std::runtime_error("cant connect");
	}
}

std::string net::FileClient::get_metadata(int cmd) {
	send_command(cmd);
	std::uint32_t size;
	asio::read(s, asio::buffer(&size, sizeof(uint32_t)));
	size = std::byteswap(size);

	std::string ret = recv_part_data(size);

	//std::string ret;
	//ret.resize(size);
	//asio::read(s, asio::buffer(ret.data(), ret.length()));
	m_msgid++;
	return ret;
}

Manifest net::FileClient::download_manifest() {
	std::istringstream data(get_metadata(4), std::ios::binary);
	//std::ofstream f("dumped.bin", std::ios::binary);
	//f << data.rdbuf();
	//f.close();
	return Manifest(data);
}

Checksum net::FileClient::download_checksums() {
	std::istringstream ss(get_metadata(6), std::ios::binary);
	return Checksum(ss);
}

std::vector<std::string> net::FileClient::get_file(unsigned fileid, int totalchunks, Index::filetype& mode) {
	const int chunks_per_call = 2;
	std::vector<std::string> chunks;

	for (int i = 0; i < totalchunks; i += chunks_per_call) {
		int chunks_to_get = totalchunks - i;
		if (chunks_to_get > chunks_per_call) {
			chunks_to_get = chunks_per_call;
		}
		unsigned retries = 0;
		while (retries < m_retries) {
			try {
				if (!m_connected) {
					connect_and_open();
				}
				mode = get_chunks(fileid, i, chunks_to_get, chunks);
				break;
			}
			catch (...) {
				s.close();
				m_connected = false;
				retries++;
			}
		}
	}
	return chunks;
}


Index::filetype net::FileClient::get_chunks(int fileid, int filestart, int numchunks, std::vector<std::string>& chunks) {
#pragma pack(push, 1)
	struct fd_t {
		uint32_t fileid;
		uint32_t filestart;
		uint32_t numchunks;
		uint8_t pad = 0;
	} fd;
#pragma pack(pop)
	fd.fileid = std::byteswap(fileid);
	fd.filestart = std::byteswap(filestart);
	fd.numchunks = std::byteswap(numchunks);
	send_command(7, reinterpret_cast<char*>(&fd), sizeof(fd));

	struct rc_t {
		uint32_t replychunks;
		uint32_t filemode;
	} rc;

	asio::read(s, asio::buffer(&rc, sizeof(rc)));
	Index::filetype ret = static_cast<Index::filetype>(std::byteswap(rc.filemode));
	
	for (unsigned i = 0; i < std::byteswap(rc.replychunks); i++) {
		chunks.push_back(receive_data_withlen());
	}

	m_msgid++;
	return ret;
}


std::vector<net::addr> net::get_fileservers(net::addr cls, unsigned app, unsigned version, short max) {
	asio::io_context io_context;

	tcp::socket s(io_context);
	
	s.connect(tcp::endpoint(cls.ip, cls.port) );

	net::pkt_cmforapp c;
	//STEAM2_SETSIZE(c);
	//c.size = sizeof(c) - 4;
	c.app = std::byteswap(app);
	c.version = std::byteswap(version);
	c.max_servers = std::byteswap(max);

	asio::write(s, asio::buffer("\x00\x00\x00\x02", 4));
	uint8_t hsbyte;
	asio::read(s, asio::buffer(&hsbyte, 1));



	asio::write(s, asio::buffer(&c, sizeof(c)));
	uint32_t size;
	asio::read(s, asio::buffer(&size, sizeof(uint32_t)));

	unsigned short server_count;
#pragma pack(push, 1)
	struct srv_t {
		uint16_t unk;
		uint16_t id;
		uint32_t s;
		uint16_t p;
		uint32_t s2;
		uint16_t p2;
	};
#pragma pack(pop)
	std::vector<net::addr> ret;
	asio::read(s, asio::buffer(&server_count, sizeof(server_count)));
	server_count = std::byteswap(server_count);
	for (int i = 0; i < server_count; i++) {
		srv_t srv;
		asio::read(s, asio::buffer(&srv, sizeof(srv)));
		net::addr a, a2;
		a.ip = asio::ip::address_v4(std::byteswap(srv.s));
		a.port = srv.p;
		a2.ip = asio::ip::address_v4(std::byteswap(srv.s2));
		a2.port = srv.p2;
		ret.push_back(a);
		ret.push_back(a2);
	}
	return ret;
}

bool net::download_cdr(addr cdr_addr, std::ostream& out_stream) {
	asio::io_context io_context;
	tcp::socket s(io_context);
	s.connect(tcp::endpoint(cdr_addr.ip, cdr_addr.port));
	char handshake[] = {'\x00', '\x00' , '\x00' ,'\x03'};
	asio::write(s, asio::buffer(handshake, sizeof(handshake)));
	char ok;
	asio::read(s,asio::buffer(&ok, sizeof(char)));
	if (!ok) {
		s.close();
		return false;
	};
	//s.send(123);
	uint32_t external_v4;
	asio::read(s, asio::buffer(&external_v4, sizeof(external_v4)));
	char unk[] = { '\x00', '\x00', '\x00', '\x15' };
	char unk2[] = { '\x09', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00' };
	asio::write(s, asio::buffer(unk, sizeof(unk)));
	asio::write(s, asio::buffer(unk2, sizeof(unk2)));
	char unk_resp[11];
	asio::read(s, asio::buffer(unk_resp, sizeof(unk_resp)));
	uint32_t size;
	asio::read(s, asio::buffer(&size, sizeof(uint32_t)));
	size = std::byteswap(size);
	std::print(std::cout, "size {}\n", size);
	char* temp = new char[size];
	asio::read(s, asio::buffer(temp, size));
	out_stream.write(temp, size);
	delete[] temp;
	return true;
}
#endif