#!/bin/bash

# List of repositories to add as submodules
repos=(
    "https://github.com/trustedsec/CS-Situational-Awareness-BOF"
    "https://github.com/rvrsh3ll/BOF_Collection"
    "https://github.com/boku7/whereami"
    "https://github.com/RiccardoAncarani/BOFs"
    "https://github.com/outflanknl/C2-Tool-Collection"
    "https://github.com/tvgdb/cobaltstrike-cat-bof"
    "https://github.com/sliverarmory/tgtdelegation"
    "https://github.com/mertdas/PrivKit"
    "https://github.com/wsummerhill/BOF-enumfiles"
    "https://github.com/boku7/xPipe"
    "https://github.com/anthemtotheego/InlineExecute-Assembly"
    "https://github.com/kyleavery/inject-assembly"
    "https://github.com/CCob/BOF.NET"
    "https://github.com/williamknows/BOF.NET"
    "https://github.com/ajpc500/BOFs"
    "https://github.com/iilegacyyii/ThreadlessInject-BOF"
    "https://github.com/rookuu/BOFs"
    "https://github.com/josephkingstone/BOFs-2"
    "https://github.com/EncodeGroup/BOF-RegSave"
    "https://github.com/rsmudge/unhook-bof"
    "https://github.com/outflanknl/WdToggle"
    "https://github.com/trustedsec/CS-Remote-OPs-BOF"
    "https://github.com/boku7/injectAmsiBypass"
    "https://github.com/boku7/injectEtwBypass"
    "https://github.com/ScriptIdiot/BOF-patchit"
    "https://github.com/cube0x0/BofRoast"
    "https://github.com/GhostPack/Koh"
    "https://github.com/RalfHacker/Kerbeus-BOF"
    "https://github.com/DallasFR/Cobalt-Clip"
    "https://github.com/CodeXTF2/ScreenshotBOF"
    "https://github.com/wavvs/nanorobeus"
    "https://github.com/EspressoCake/Defender-Exclusions-Creator-BOF"
    "https://github.com/Tw1sm/SQL-BOF"
    "https://github.com/Meckazin/ChromeKatz"
    "https://github.com/Cobalt-Strike/bof_template"
    "https://github.com/fortalice/bofhound"
    "https://github.com/WKL-Sec/HiddenDesktop"
)

# Add each repository as a submodule
for repo in "${repos[@]}"; do
    name=$(basename "$repo" .git)
    echo "Adding $repo as a submodule..."
    git submodule add "$repo" "submodules/$name"
done

# Initialize and update all submodules
git submodule update --init --recursive

echo "All repositories have been added as submodules!"