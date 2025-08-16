set_rules("mode.release", "mode.debug")

build_net = false

if build_net then
	add_requires("zlib-ng", "cryptopp", "asio")
else
	add_requires("zlib-ng", "cryptopp")
end

target("extract")
	set_kind("binary")
	if build_net then
		add_defines("STEAM2_BUILD_NET")
	end
	-- set_symbols("debug")	
	set_languages("c++23")
	add_files("src/*.cpp")
	set_symbols("debug")
	add_includedirs("include/")
	add_includedirs("include/thirdparty/")
	add_packages("zlib-ng", "cryptopp")
	after_build(function (target)
		os.cp(target:targetfile(), "./dist/")
	end)