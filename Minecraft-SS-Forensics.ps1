<#
.SYNOPSIS
    Minecraft-SS-Forensics.ps1 – Read‑only forensic scanner for Minecraft anti‑cheat investigations.

.DESCRIPTION
    Scans a selected mods folder and system artifacts for indicators of cheating,
    injection, obfuscation, and self‑destruct evidence. Designed for authorized server‑staff
    use only. Produces HTML, JSON, CSV, and summary reports.

    All scanning is read‑only. No files are modified, deleted, quarantined, or executed.
    No network calls are made. Evidence is preserved with timestamps and metadata.

    This script is self‑contained – no external dependencies required.

.PARAMETER OutputPath
    Folder where reports will be saved. Defaults to Desktop\Forensics_Report_<timestamp>.

.PARAMETER DeepScan
    Perform a thorough system scan (USN Journal, Prefetch, Recycle Bin, etc.).
    This may take longer and requires administrator privileges for some artifacts.

.PARAMETER HashFiles
    Calculate SHA‑256 hashes for relevant files (mods, executables, etc.) and include them
    in the report.

.PARAMETER Help
    Display this help message.

.EXAMPLE
    .\Minecraft-SS-Forensics.ps1 -DeepScan -HashFiles

    Scans the selected mods folder and system with deep scan and hashing.

.NOTES
    Tool:    MagiciansReveal V3
    Author:  Tim$erz
    Version: 3.0.3
    License: MIT (for authorized use only)
    Disclaimer: This tool provides indicators for analyst review. Findings are not
               conclusive proof of cheating and require human verification.
#>

[CmdletBinding()]
param(
    [string]$OutputPath,
    [switch]$DeepScan,
    [switch]$HashFiles,
    [switch]$Help
)

if ($Help) {
    Get-Help $MyInvocation.MyCommand.Path -Detailed
    exit 0
}

#region Configuration (Editable)
$script:Config = @{
    CheatClientAliases = @(
        "LiquidBounce", "LiquidBounce Nextgen", "Wurst", "Meteor", "BleachHack", "Impact",
        "Inertia", "Aristois", "Vape", "Future", "RusherHack", "Pyro", "Boze", "Kami Blue",
        "ThunderHack", "Raven", "Raven B+", "Rise", "Exhibition", "Sigma", "Wolfram",
        "FDP Client", "Tenacity", "Dortware", "Astolfo", "Moon", "Novo", "Zeroday",
        "Whiteout", "Baritone",
        "Doomsday", "DoomsdayClient", "doomsday", "VapeClient", "VapeLite", "vape.gg",
        "MeteorClient", "meteorclient", "meteordevelopment", "WurstClient",
        "SigmaClient", "Novoware", "GameSense", "OsirisClient", "CosmosClient",
        "AzuraClient", "ArgonClient", "KryptonClient", "PrestigeClient", "FutureClient",
        "Pandaware", "IntentClient", "Novoclient", "Hellion", "VirginClient",
        "XenonClient", "GypsyClient", "Dqrkis", "WalksyOptimizer", "LWFH Crystal",
        "catlean", "AsteriaClient", "198Macros"
    )
    ModuleIndicators = @(
        "KillAura", "AimAssist", "TriggerBot", "AutoClicker", "Reach", "Velocity",
        "AntiKnockback", "Fly", "Speed", "Bhop", "Strafe", "Scaffold", "Tower", "Step",
        "LongJump", "Jesus", "NoFall", "Phase", "Blink", "Timer", "Freecam", "XRay",
        "ESP", "Tracers", "StorageESP", "FullBright", "ChestStealer", "InventoryMove",
        "AutoArmor", "AutoTotem", "FastPlace", "FastBreak", "Nuker", "Rotation",
        "Criticals", "Disabler", "PacketFly", "NoSlow", "SafeWalk", "Backtrack",
        "LegitAssist", "Hitboxes", "AutoCrystal", "CrystalAura", "Surround", "SelfTrap",
        "AnchorAura", "BedAura", "AutoMace", "ShieldBreaker"
    )
    WeakModules = @("ESP", "Speed", "FullBright", "Hitboxes")
    PackagePatterns = @(
        "\b(?:net|com|org|io|xyz)\.(?:minecraft|mc|client)\.(?:cheat|hack|mod|module)\b",
        "\b(?:me|club|wtf|cc)\.(?:[a-z]+)\.(?:client|hack)\b"
    )
    DomainPatterns = @(
        "\b(?:[a-zA-Z0-9-]+\.)+(?:com|org|net|io|xyz|club|gg|rip|top|tk|ml|ga|cf|us|biz|info|name|tv|me|eu)\b",
        "vape\.gg|vapeclient\.com|meteorclient\.com|liquidbounce\.net|wurstclient\.net",
        "sigmaclient\.com|novoware\.cc|gamesense\.pw|osirisclient\.com|prestigeclient\.vip",
        "dqrkis\.xyz|orchard\.gg|intent\.store|rise\.today|riseclient\.com"
    )
    SuspiciousFilePatterns = @(
        ".*hack.*\.jar", ".*cheat.*\.jar", ".*client.*\.jar", ".*inject.*\.dll",
        ".*agent.*\.jar", ".*loader.*\.jar"
    )
    KnownLegitMods = @(
        "fabric-api", "fabric-loader", "forge", "neoforge", "quilt-loader",
        "sodium", "lithium", "phosphor", "iris", "modmenu", "cloth-config",
        "architectury", "krypton", "ferritecore", "lazydfu", "starlight",
        "entityculling", "dynamicfps", "spark", "servercore", "vmp"
    )
    AllowlistDomains = @(
        "modrinth.com", "curseforge.com", "minecraft.net", "mojang.com",
        "github.com", "fabricmc.net", "quiltmc.org", "neoforged.net"
    )
    AllowlistPaths = @(
        "$env:ProgramFiles\Java",
        "$env:ProgramFiles\Common Files",
        "$env:windir\System32",
        "$env:windir\SysWOW64"
    )
    SeverityWeights = @{
        "Informational" = 0
        "Low"          = 10
        "Medium"       = 30
        "High"         = 60
        "Critical"     = 90
    }
    MaxScanFileSize = 100MB
    RegexRules = @(
        @{ Name = "Webhook"; Pattern = 'https?://discord(?:app)?\.com/api/webhooks/[\w-]+/[\w-]+' },
        @{ Name = "DiscordInvite"; Pattern = 'discord(?:\.gg|app\.com/invite)/[\w-]+' },
        @{ Name = "Base64"; Pattern = '[A-Za-z0-9+/]{40,}={0,2}' },
        @{ Name = "IPv4"; Pattern = '\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b' },
        @{ Name = "URL"; Pattern = 'https?://[^\s"<>]+' }
    )
    OutputFormat = @{
        HtmlTitle = "Minecraft Forensic Report"
        CsvDelimiter = ","
        JsonIndent = 4
    }
}

$script:SuspiciousPatterns = @(
    "AimAssist", "AnchorTweaks", "AutoAnchor", "AutoCrystal", "AutoDoubleHand", "JDWP.VirtualMachine.AllModules",
    "AutoHitCrystal", "AutoPot", "AutoTotem", "AutoArmor", "InventoryTotem",
    "LegitTotem", "PingSpoof", "SelfDestruct",
    "ShieldBreaker", "TriggerBot", "AxeSpam", "WebMacro",
    "FastPlace", "WalskyOptimizer", "WalksyOptimizer", "walsky.optimizer",
    "WalksyCrystalOptimizerMod", "Donut", "Replace Mod",
    "ShieldDisabler", "SilentAim", "Totem Hit", "Wtap", "FakeLag",
    "dev.virel", "orchard",
    "BlockESP", "dev.krypton", "dev/krypton", "skid.krypton", "skid/krypton",  "AntiMissClick",
    "LagReach", "PopSwitch", "SprintReset", "ChestSteal", "AntiBot",
    "ElytraSwap", "FastXP", "FastExp", "Refill",  "AirAnchor",
    "jnativehook", "FakeInv", "HoverTotem", "AutoClicker", "AutoFirework",
    "PackSpoof", "Antiknockback", "catlean",
    "AuthBypass", "Asteria", "Prestige", "AutoEat", "AutoMine",
    "MaceSwap",  "Macro198", "StunSlam", "SafeAnchor", "DoubleAnchor", "AutoTPA", "BaseFinder", "Xenon", "gypsy",
    "AutoPotRefill", "WalksyOptimizer", "KeyPearl", "AimAssist", "AutoNethPot", "AutoDtap",
    "TriggerBot", "AutoWeb", "AnchorAction",
    "org.chainlibs.module.impl.modules.Crystal.Y",
    "org.chainlibs.module.impl.modules.Crystal.bF",
    "org.chainlibs.module.impl.modules.Crystal.bM",
    "org.chainlibs.module.impl.modules.Crystal.bY",
    "org.chainlibs.module.impl.modules.Crystal.bq",
    "org.chainlibs.module.impl.modules.Crystal.cv",
    "org.chainlibs.module.impl.modules.Crystal.o",
    "org.chainlibs.module.impl.modules.Blatant.I",
    "org.chainlibs.module.impl.modules.Blatant.bR",
    "org.chainlibs.module.impl.modules.Blatant.bx",
    "org.chainlibs.module.impl.modules.Blatant.cj",
    "org.chainlibs.module.impl.modules.Blatant.dk",
    "imgui.gl3", "imgui.glfw",
    "BowAim", "Criticals", "Fakenick", "FakeItem",
    "invsee", "ItemExploit", "Hellion", "hellion",
    "LicenseCheckMixin", "ClientPlayerInteractionManagerAccessor",
    "ClientPlayerEntityMixim", "dev.gambleclient", "obfuscatedAuth",
    "phantom-refmap.json", "xyz.greaj",
    "じ.class", "ふ.class", "ぶ.class", "ぷ.class", "た.class",
    "ね.class", "そ.class", "な.class", "ど.class", "ぐ.class",
    "ず.class", "で.class", "つ.class", "べ.class", "せ.class",
    "と.class", "み.class", "び.class", "す.class", "の.class"
)

$script:CheatStrings = @(
    "AutoCrystal", "autocrystal", "auto crystal", "cw crystal", "JDWP.VirtualMachine.AllModules",
    "dontPlaceCrystal", "dontBreakCrystal",
    "dev.virel", "orchard",
    "AutoHitCrystal", "autohitcrystal", "canPlaceCrystalServer", "healPotSlot",
    "ＡｕｔｏＣｒｙｓｔａｌ", "Ａｕｔｏ Ｃｒｙｓｔａｌ",
    "ＡｕｔｏＨｉｔＣｒｙｓｔａｌ",
    "AutoAnchor", "autoanchor", "auto anchor", "DoubleAnchor",
     "HasAnchor", "anchortweaks", "anchor macro", "safe anchor", "safeanchor",
    "SafeAnchor", "AirAnchor",
    "ＡｕｔｏＡｎｃｈｏｒ", "Ａｕｔｏ Ａｎｃｈｏｒ",
    "ＤｏｕｂｌｅＡｎｃｈｏｒ", "Ｄｏｕｂｌｅ Ａｎｃｈｏｒ",
    "ＳａｆｅＡｎｃｈｏｒ", "Ｓａｆｅ Ａｎｃｈｏｒ",
    "Ａｎｃｈｏｒ Ｍａｃｒｏ", "anchorMacro",
    "AutoTotem", "autototem", "auto totem", "InventoryTotem",
    "inventorytotem", "HoverTotem", "hover totem", "legittotem",
    "ＡｕｔｏＴｏｔｅｍ", "Ａｕｔｏ Ｔｏｔｅｍ",
    "ＨｏｖｅｒＴｏｔｅｍ", "Ｈｏｖｅｒ Ｔｏｔｅｍ",
    "ＩｎｖｅｎｔｏｒｙＴｏｔｅｍ", "Ａｕｔｏ Ｉｎｖｅｎｔｏｒｙ Ｔｏｔｅｍ",
    "Ａｕｔｏ Ｔｏｔｅｍ Ｈｉｔ",
    "AutoPot", "autopot", "auto pot", "speedPotSlot", "strengthPotSlot",
    "AutoArmor", "autoarmor", "auto armor",
    "ＡｕｔｏＰｏｔ", "Ａｕｔｏ Ｐｏｔ",
    "Ａｕｔｏ Ｐｏｔ Ｒｅｆｉｌｌ", "AutoPotRefill",
    "ＡｕｔｏＡｒｍｏｒ", "Ａｕｔｏ Ａｒｍｏｒ",
    "preventSwordBlockBreaking", "preventSwordBlockAttack",
    "ShieldDisabler", "ShieldBreaker",
    "ＳｈｉｅｌｄＤｉｓａｂｌｅｒ", "Ｓｈｉｅｌｄ Ｄｉｓａｂｌｅｒ",
    "Breaking shield with axe...",
    "AutoDoubleHand", "autodoublehand", "auto double hand",
    "ＡｕｔｏＤｏｕｂｌｅＨａｎｄ", "Ａｕｔｏ Ｄｏｕｂｌｅ Ｈａｎｄ",
    "AutoClicker",
    "ＡｕｔｏＣｌｉｃｋｅｒ",
    "Failed to switch to mace after axe!",
    "AutoMace", "MaceSwap", "SpearSwap",
    "ＡｕｔｏＭａｃｅ", "Ａｕｔｏ Ｍａｃｅ",
    "ＭａｃｅＳｗａｐ", "Ｍａｃｅ Ｓｗａｐ",
    "Ｓｐｅａｒ Ｓｗａｐ", "Ａｕｔｏｍａｔｉｃａｌｌｙ ａｘｅ ａｎｄ ｍａｃｅ ｓｈｉｅｌｄｅｄ ｐｌａｙｅｒｓ",
    "Ｓｔｕｎ Ｓｌａｍ", "StunSlam",
    "Donut", "JumpReset", "axespam", "axe spam",
    
    "findKnockbackSword", "attackRegisteredThisClick",
    "AimAssist", "aimassist", "aim assist",
    "triggerbot", "trigger bot",
    "ＡｉｍＡｓｓｉｓｔ", "Ａｉｍ Ａｓｓｉｓｔ",
    "ＴｒｉｇｇｅｒＢｏｔ", "Ｔｒｉｇｇｅｒ Ｂｏｔ",
    "Silent Rotations", "SilentRotations",
    "Ｓｉｌｅｎｔ Ｒｏｔａｔｉｏｎｓ",
    "FakeInv", "swapBackToOriginalSlot",
    "FakeLag", "pingspoof", "ping spoof",
    "ＦａｋｅＬａｇ", "Ｆａｋｅ Ｌａｇ",
    "fakePunch", "Fake Punch",
    "Ｆａｋｅ Ｐｕｎｃｈ",
    "mace_swap", "quick_strike", "macro_198", "stun_slam",
    "safe_anchor", "double_anchor", "auto_pot_refill",
    "walksy_optimizer", "key_pearl", "aim_assist",
    "auto_neth_pot", "auto_dtap", "trigger_bot", "auto_web",
    "DOUBLE_ESCAPE", "DOUBLE_RIGHTCLICK_FIRST", "DOUBLE_RIGHTCLICK_SECOND",
    "POST_CYCLE_DELAY", "PLACE_OBI", "WAIT_OBI", "PLACE_CRYSTAL", "BREAK_CRYSTAL",
    "ROTATING_DOWN", "ROTATING_BACK", "REFILLING", "PLANTING", "BONEMEALING",
    "AnchorAction", "Places two anchors for massive damage",
    "REOFFHAND_TOTEM",
    "webmacro", "web macro",
    "AntiWeb", "AutoWeb",
    "Ａｎｔｉ Ｗｅｂ", "ＡｕｔｏＷｅｂ",
    "Ｐｌａｃｅｓ Ｗｅｂｓ Ｏｎ Ｅｎｅｍｉｅｓ",
    "lvstrng", "dqrkis", "selfdestruct", "self destruct",
    "WalksyCrystalOptimizerMod", "WalksyOptimizer", "WalskyOptimizer",
    "Ｗａｌｋｓｙ Ｏｐｔｉｍｉｚｅｒ",
    "autoCrystalPlaceClock",
    "AutoFirework", "ElytraSwap", "FastXP", "FastExp", "NoJumpDelay",
    "ＥｌｙｔｒａＳｗａｐ", "Ｅｌｙｔｒａ Ｓｗａｐ",
    "PackSpoof", "Antiknockback", "catlean",
    "AuthBypass", "obfuscatedAuth", "LicenseCheckMixin",
    "BaseFinder", "invsee", "ItemExploit",
    "FreezePlayer",
    "Ｆｒｅｅｃａｍ", "Ｍｏｖｅ ｆｒｅｅｌｙ ｔｈｒｏｕｇｈ ｗａｌｌｓ",
    "Ｎｏ Ｃｌｉｐ", "Ｆｒｅｅｚｅ Ｐｌａｙｅｒ",
    "LWFH Crystal", "JDWP.VirtualMachine.AllModules",
    "ＬＷＦＨ Ｃｒｙｓｔａｌ",
    "KeyPearl", "LootYeeter",
    "ＫｅｙＰｅａｒｌ", "Ｋｅｙ Ｐｅａｒｌ",
    "Ｌｏｏｔ Ｙｅｅｔｅｒ",
    "FastPlace",
    "Ｆａｓｔ Ｐｌａｃｅ", "Ｐｌａｃｅ ｂｌｏｃｋｓ ｆａｓｔｅｒ",
    "AutoBreach",
    "Ａｕｔｏ Ｂｒｅａｃｈ",
    "setBlockBreakingCooldown", "getBlockBreakingCooldown", "blockBreakingCooldown",
    "onBlockBreaking", "setItemUseCooldown",
    "invokeDoAttack", "invokeDoItemUse", "invokeOnMouseButton",
    "onPushOutOfBlocks", "onIsGlowing",
    "Automatically switches to sword when hitting with totem",
    "arrayOfString", "POT_CHEATS",
    "Dqrkis Client", "Entity.isGlowing",
    "Activate Key", "Ａｃｔｉｖａｔｅ Ｋｅｙ",
    "Click Simulation", "Ｃｌｉｃｋ Ｓｉｍｕｌａｔｉｏｎ",
    "On RMB", "Ｏｎ ＲＭＢ",
    "No Count Glitch", "Ｎｏ Ｃｏｕｎｔ Ｇｌｉｔｃｈ",
    "No Bounce", "NoBounce", "Ｎｏ Ｂｏｕｎｃｅ", "ＮｏＢｏｕｎｃｅ",
    "Ｒｅｍｏｖｅｓ ｔｈｅ ｃｒｙｓｔａｌ ｂｏｕｎｃｅ ａｎｉｍａｔｉｏｎ",
    "Place Delay", "Ｐｌａｃｅ Ｄｅｌａｙ",
    "Break Delay", "Ｂｒｅａｋ Ｄｅｌａｙ",
     "Ｆａｓｔ Ｍｏｄｅ",
    "Place Chance", "Ｐｌａｃｅ Ｃｈａｎｃｅ",
    "Break Chance", "Ｂｒｅａｋ Ｃｈａｎｃｅ",
    "Stop On Kill", "Ｓｔｏｐ Ｏｎ Ｋｉｌｌ",
    "Ｄａｍａｇｅ Ｔｉｃｋ", "damagetick",
    "Anti Weakness", "Ａｎｔｉ Ｗｅａｋｎｅｓｓ",
    "Particle Chance", "Ｐａｒｔｉｃｌｅ Ｃｈａｎｃｅ",
    "Trigger Key", "Ｔｒｉｇｇｅｒ Ｋｅｙ",
    "Switch Delay", "Ｓｗｉｔｃｈ Ｄｅｌａｙ",
    "Totem Slot", "Ｔｏｔｅｍ Ｓｌｏｔ",
    "Silent Rotations", "Ｓｉｌｅｎｔ Ｒｏｔａｔｉｏｎｓ",
    "Smooth Rotations", "Ｓｍｏｏｔｈ Ｒｏｔａｔｉｏｎｓ",
    "Rotation Speed", "Ｒｏｔａｔｉｏｎ Ｓｐｅｅｄ",
    "Use Easing", "Ｕｓｅ Ｅａｓｉｎｇ",
    "Easing Strength", "Ｅａｓｉｎｇ Ｓｔｒｅｎｇｔｈ",
    "While Use", "Ｗｈｉｌｅ Ｕｓｅ",
    "Stop on Kill", "Ｓｔｏｐ ｏｎ Ｋｉｌｌ",
    "Click Simulation", "Ｃｌｉｃｋ Ｓｉｍｕｌａｔｉｏｎ",
    "Glowstone Delay", "Ｇｌｏｗｓｔｏｎｅ Ｄｅｌａｙ",
    "Glowstone Chance", "Ｇｌｏｗｓｔｏｎｅ Ｃｈａｎｃｅ",
    "Explode Delay", "Ｅｘｐｌｏｄｅ Ｄｅｌａｙ",
    "Explode Chance", "Ｅｘｐｌｏｄｅ Ｃｈａｎｃｅ",
    "Explode Slot", "Ｅｘｐｌｏｄｅ Ｓｌｏｔ",
    "Only Charge", "Ｏｎｌｙ Ｃｈａｒｇｅ",
    "Anchor Macro", "Ａｎｃｈｏｒ Ｍａｃｒｏ",
    "Reach Distance", "Ｒｅａｃｈ Ｄｉｓｔａｎｃｅ",
    "Min Height", "Ｍｉｎ Ｈｅｉｇｈｔ",
    "Min Fall Speed", "Ｍｉｎ Ｆａｌｌ Ｓｐｅｅｄ",
    "Attack Delay", "Ａｔｔａｃｋ Ｄｅｌａｙ",
    "Breach Delay", "Ｂｒｅａｃｈ Ｄｅｌａｙ",
    "Require Elytra", "Ｒｅｑｕｉｒｅ Ｅｌｙｔｒａ",
    "Auto Switch Back", "Ａｕｔｏ Ｓｗｉｔｃｈ Ｂａｃｋ",
    "Check Line of Sight", "Ｃｈｅｃｋ Ｌｉｎｅ ｏｆ Ｓｉｇｈｔ",
    "Only When Falling", "Ｏｎｌｙ Ｗｈｅｎ Ｆａｌｌｉｎｇ",
    "Require Crit", "Ｒｅｑｕｉｒｅ Ｃｒｉｔ",
    "Show Status Display", "Ｓｈｏｗ Ｓｔａｔｕｓ Ｄｉｓｐｌａｙ",
    "Stop On Crystal", "Ｓｔｏｐ Ｏｎ Ｃｒｙｓｔａｌ",
    "Check Shield", "Ｃｈｅｃｋ Ｓｈｉｅｌｄ",
    "On Pop", "Ｏｎ Ｐｏｐ",
    "Predict Damage", "Ｐｒｅｄｉｃｔ Ｄａｍａｇｅ",
    "On Ground", "Ｏｎ Ｇｒｏｕｎｄ",
    "Check Players", "Ｃｈｅｃｋ Ｐｌａｙｅｒｓ",
    "Predict Crystals", "Ｐｒｅｄｉｃｔ Ｃｒｙｓｔａｌｓ",
    "Check Aim", "Ｃｈｅｃｋ Ａｉｍ",
    "Check Items", "Ｃｈｅｃｋ Ｉｔｅｍｓ",
    "Activates Above", "Ａｃｔｉｖａｔｅｓ Ａｂｏｖｅ",
    "Blatant", "Ｂｌａｔａｎｔ",
    "Force Totem", "Ｆｏｒｃｅ Ｔｏｔｅｍ",
    "Stay Open For", "Ｓｔａｙ Ｏｐｅｎ Ｆｏｒ",
    "Auto Inventory Totem", "Ａｕｔｏ Ｉｎｖｅｎｔｏｒｙ Ｔｏｔｅｍ",
    "Only On Pop", "Ｏｎｌｙ Ｏｎ Ｐｏｐ",
    "Vertical Speed", "Ｖｅｒｔｉｃａｌ Ｓｐｅｅｄ",
    "Hover Totem", "Ｈｏｖｅｒ Ｔｏｔｅｍ",
    "Swap Speed", "Ｓｗａｐ Ｓｐｅｅｄ",
    "Strict One-Tick", "Ｓｔｒｉｃｔ Ｏｎｅ－Ｔｉｃｋ",
    "Mace Priority", "Ｍａｃｅ Ｐｒｉｏｒｉｔｙ",
    "Min Totems", "Ｍｉｎ Ｔｏｔｅｍｓ",
    "Min Pearls", "Ｍｉｎ Ｐｅａｒｌｓ",
    "Totem First", "Ｔｏｔｅｍ Ｆｉｒｓｔ",
    "Drop Interval", "Ｄｒｏｐ Ｉｎｔｅｒｖａｌ",
    "Random Pattern", "Ｒａｎｄｏｍ Ｐａｔｔｅｒｎ",
    "Loot Yeeter", "Ｌｏｏｔ Ｙｅｅｔｅｒ",
    "Horizontal Aim Speed", "Ｈｏｒｉｚｏｎｔａｌ Ａｉｍ Ｓｐｅｅｄ",
    "Vertical Aim Speed", "Ｖｅｒｔｉｃａｌ Ａｉｍ Ｓｐｅｅｄ",
    "Include Head", "Ｉｎｃｌｕｄｅ Ｈｅａｄ",
    "Web Delay", "Ｗｅｂ Ｄｅｌａｙ",
    "Holding Web", "Ｈｏｌｄｉｎｇ Ｗｅｂ",
    "Not When Affects Player", "Ｎｏｔ Ｗｈｅｎ Ａｆｆｅｃｔｓ Ｐｌａｙｅｒ",
    "Hit Delay", "Ｈｉｔ Ｄｅｌａｙ",
    "Ｓｗｉｔｃｈ Ｂａｃｋ",
    "Require Hold Axe", "Ｒｅｑｕｉｒｅ Ｈｏｌｄ Ａｘｅ",
    "Fake Punch", "Ｆａｋｅ Ｐｕｎｃｈ",
    "placeInterval", "breakInterval", "stopOnKill",
    "activateOnRightClick", "holdCrystal",
    "ｐｌａｃｅＩｎｔｅｒｖａｌ", "ｂｒｅａｋＩｎｔｅｒｖａｌ",
    "ｓｔｏｐＯｎＫｉｌｌ", "ａｃｔｉｖａｔｅＯｎＲｉｇｈｔＣｌｉｃｋ",
    "ｄａｍａｇｅｔｉｃｋ", "ｈｏｌｄＣｒｙｓｔａｌ",
    "ｆａｋｅＰｕｎｃｈ",
    "Ｒｅｆｉｌｌｓ ｙｏｕｒ ｈｏｔｂａｒ ｗｉｔｈ ｐｏｔｉｏｎｓ",
    "Ｋｅｐｓ ｙｏｕ ｓｐｒｉｎｔｉｎｇ ａｔ ａｌｌ ｔｉｍｅｓ",
    "Ｐｌａｃｅｓ ａｎｃｈｏｒ， ｃｈａｒｇｅｓ ｉｔ， ｐｒｏｔｅｃｔｓ ｙｏｕ， ａｎｄ ｅｘｐｌｏｄｅｓ",
    "Ａｕｔｏ ｓｗａｐ ｔｏ ｓｐｅａｒ ｏｎ ａｔｔａｃｋ",
    "Macro Key", "Ａｕｔｏ Ｐｏｔ", "Ｍａｃｒｏ Ｋｅｙ",
    "KillAura", "ClickAura", "MultiAura", "ForceField", "LegitAura",
    "AimBot", "AutoAim", "SilentAim", "AimLock", "HeadSnap",
    "CrystalAura",
    "AnchorAura", "AnchorFill", "AnchorPlace",
    "BedAura", "AutoBed", "BedBomb", "BedPlace",
    "BowAimbot", "BowSpam", "AutoBow",
    "AutoCrit", "CritBypass", "AlwaysCrit", "CriticalHit",
    "ReachHack", "ExtendReach", "LongReach", "HitboxExpand",
    "AntiKB", "NoKnockback", "GrimVelocity", "GrimDisabler", "VelocitySpoof", "KBReduce",
    "OffhandTotem", "TotemSwitch",
    "AutoWeapon", "AutoSword", "AutoCity", "Burrow", "SelfTrap",
    "HoleFiller", "AntiSurround", "AntiBurrow",
    "WTap", "TargetStrafe", "AutoGap", "AutoPearl",
    "FlyHack", "CreativeFlight", "BoatFly", "PacketFly", "AirJump",
    "SpeedHack", "BHop", "BunnyHop",
    "AntiFall", "NoFallDamage", "SafeFall",
    "StepHack", "FastClimb", "AutoStep", "HighStep",
    "WaterWalk", "LiquidWalk", "LavaWalk",
    "NoSlow", "NoSlowdown", "NoWeb", "NoSoulSand",
    "WallHack",
    "ElytraSpeed", "InstantElytra",
    "ScaffoldWalk", "FastBridge", "BuildHelper", "AutoBridge",
    "Nuker", "NukerLegit", "InstantBreak",
    "GhostHand", "NoSwing",
    "PlaceAssist", "AirPlace", "AutoPlace", "InstantPlace",
    "PlayerESP", "MobESP", "ItemESP", "StorageESP", "ChestESP",
    "Tracers", "NameTagsHack",
    "XRayHack", "OreFinder", "CaveFinder", "OreESP",
    "NewChunks", "ChunkBorders", "TunnelFinder",
    "TargetHUD", "ReachDisplay",
    "DoubleClicker", "JitterClick", "ButterflyClick", "CPSBoost",
    "ChestStealer", "InvManager", "InvMovebypass",
    "AutoSprint", "AntiAFK", "AutoRespawn",
    "PopSwitch",
    "FakeLatency", "FakePing", "SpoofRotation", "PositionSpoof",
    "GameSpeed", "SpeedTimer",
     "GrimBypass", "VulcanBypass", "MatrixBypass",
    "AACBypass", "VerusDisabler", "IntaveBypass", "WatchdogBypass",
    "PacketMine", "PacketWalk", "PacketSneak", "PacketCancel", "PacketDupe", "PacketSpam",
    "SelfDestruct", "HideClient",
    "SessionStealer", "TokenLogger", "TokenGrabber", "DiscordToken",
    "RemoteAccess", "ReverseShell", "C2Server", "Backdoor", "KeyLogger",
    "StashFinder", "TrailFinder",
    "imgui.binding",
    "JNativeHook", "GlobalScreen", "NativeKeyListener",
    "client-refmap.json", "cheat-refmap.json",
    "aHR0cDovL2FwaS5ub3ZhY2xpZW50LmxvbC93ZWJob29rLnR4dA==",
    "meteordevelopment", "cc/novoline",
    "com/alan/clients", "club/maxstats", "wtf/moonlight",
    "me/zeroeightsix/kami", "net/ccbluex", "today/opai",
    "net/minecraft/injection", "org/chainlibs/module/impl/modules",
    "xyz/greaj", "com/cheatbreaker", "com/moonsworth",
    "doomsdayclient", "DoomsdayClient", "doomsday.jar",
    "novaclient", "api.novaclient.lol",
    "WalksyOptimizer", "LWFH Crystal",
    "vape.gg", "vapeclient", "VapeClient", "VapeLite",
    "intent.store", "IntentClient",
    "rise.today", "riseclient.com",
    "meteor-client", "meteorclient", "meteordevelopment.meteorclient",
    "liquidbounce", "fdp-client", "net.ccbluex",
    "novoware", "novoclient",
    "aristois", "impactclient", "azura",
    "pandaware", "skilled", "moonClient", "astolfo",
    "futureClient", "konas", "rusherhack", "inertia", "exhibition",
    "dev.krypton", "dev/krypton", "skid.krypton", "skid/krypton",
     "VirginClient", "virgin client",
    "catlean", "CatleanClient", "catlean client",
     "ArgonClient", "argon client",
    "Asteria", "AsteriaClient", "asteria client",
    "Prestige", "PrestigeClient", "prestige client", "prestigeclient.vip",
    "gypsy", "GypsyClient", "gypsy client",
    "Xenon", "XenonClient", "xenon client",
     "GrimClient", "grim client",
    "phantom-refmap.json",
     "dqrkis.xyz", "Dqrkis Client"
)
#endregion

#region Initialization and Authorization
function Confirm-Authorization {
    Write-Host "`n⚠️  This tool is for authorized server-staff use only." -ForegroundColor Yellow
    Write-Host "It performs read‑only scans and does not modify any files." -ForegroundColor Gray
    Write-Host "Do you have explicit authorization to run this scan on this system?" -ForegroundColor Cyan
    Write-Host "Type 'YES' to continue or any other key to exit: " -NoNewline
    $response = Read-Host
    if ($response -ne "YES") {
        Write-Host "Authorization not confirmed. Exiting." -ForegroundColor Red
        exit 0
    }
    Write-Host "Authorization confirmed. Starting scan..." -ForegroundColor Green
}

function Check-MinecraftRunning {
    $mcProc = Get-Process javaw -ErrorAction SilentlyContinue
    if (-not $mcProc) { $mcProc = Get-Process java -ErrorAction SilentlyContinue }
    if (-not $mcProc) {
        Write-Host "❌ Minecraft is not running (no javaw/java process found)." -ForegroundColor Red
        Write-Host "Please launch Minecraft and run this tool again." -ForegroundColor Yellow
        Write-Host "Press any key to exit..." -ForegroundColor Gray
        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        exit 1
    }
    return $mcProc
}

Confirm-Authorization

$mcProc = Check-MinecraftRunning
$mcPid = $mcProc[0].Id
$mcStart = $mcProc[0].StartTime
$uptime = (Get-Date) - $mcStart

# Set output path to Desktop by default to avoid permission issues
if (-not $OutputPath) {
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $desktop = [Environment]::GetFolderPath("Desktop")
    $OutputPath = Join-Path -Path $desktop -ChildPath "Forensics_Report_$timestamp"
}

# Ensure the directory exists
try {
    New-Item -ItemType Directory -Path $OutputPath -Force -ErrorAction Stop | Out-Null
} catch {
    Write-Warning "Could not create output directory at $OutputPath. Using TEMP folder."
    $OutputPath = Join-Path -Path $env:TEMP -ChildPath "Forensics_Report_$timestamp"
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Warning "Not running as Administrator. Some deep system scans (USN Journal, Prefetch, etc.) may be limited."
}

#endregion

#region Helper Functions
function Get-NormalizedPath {
    param([string]$Path)
    try { return [System.IO.Path]::GetFullPath($Path) } catch { return $Path }
}

function Get-FileInfo {
    param([string]$Path)
    $item = Get-Item -Path $Path -ErrorAction SilentlyContinue
    if ($item) {
        return [PSCustomObject]@{
            FullName = $item.FullName
            Name = $item.Name
            Length = $item.Length
            CreationTime = $item.CreationTimeUtc
            LastWriteTime = $item.LastWriteTimeUtc
            LastAccessTime = $item.LastAccessTimeUtc
            Attributes = $item.Attributes
            Owner = (Get-Acl -Path $Path -ErrorAction SilentlyContinue).Owner
        }
    }
    return $null
}

function Get-FileHashIfRequested {
    param([string]$Path)
    if ($HashFiles -and (Test-Path $Path)) {
        try {
            $hash = Get-FileHash -Path $Path -Algorithm SHA256 -ErrorAction Stop
            return $hash.Hash
        } catch { return $null }
    }
    return $null
}

function Test-FileSizeLimit {
    param([string]$Path)
    try {
        $size = (Get-Item -Path $Path -ErrorAction Stop).Length
        if ($size -gt $Config.MaxScanFileSize) { return $false }
        return $true
    } catch { return $false }
}

function Get-StringPatternMatches {
    param([string]$Content)
    $matches = @()
    foreach ($rule in $Config.RegexRules) {
        $regex = [regex]$rule.Pattern
        $m = $regex.Matches($Content)
        foreach ($match in $m) {
            $matches += [PSCustomObject]@{
                Rule = $rule.Name
                Value = $match.Value
            }
        }
    }
    return $matches
}
#endregion

#region Scanning Functions

function Scan-ModsFolder {
    param([string]$FolderPath)
    Write-Host "Scanning mods folder: $FolderPath" -ForegroundColor Cyan
    $findings = @()
    if (-not (Test-Path $FolderPath -PathType Container)) {
        Write-Host "❌ Folder not found: $FolderPath" -ForegroundColor Red
        return $findings
    }
    $jarFiles = Get-ChildItem -Path $FolderPath -Filter "*.jar" -File -ErrorAction SilentlyContinue
    if ($jarFiles.Count -eq 0) {
        Write-Host "No JAR files found in $FolderPath" -ForegroundColor Yellow
        return $findings
    }
    Write-Host "Found $($jarFiles.Count) JAR files to scan." -ForegroundColor Green
    foreach ($jar in $jarFiles) {
        $hash = if ($HashFiles) { Get-FileHashIfRequested -Path $jar.FullName } else { $null }
        $findings += [PSCustomObject]@{
            Category = "Mods"
            File = $jar.Name
            Path = $jar.FullName
            Hash = $hash
            Size = $jar.Length
            LastWrite = $jar.LastWriteTimeUtc
        }
        # Check inside JAR for suspicious strings (basic)
        try {
            $zip = [System.IO.Compression.ZipFile]::OpenRead($jar.FullName)
            foreach ($entry in $zip.Entries) {
                $entryName = $entry.FullName
                if ($entryName -match "\.class$") {
                    if ($entryName -match $Config.PackagePatterns -or $entryName -match $Config.ModuleIndicators) {
                        $findings += [PSCustomObject]@{
                            Category = "SuspiciousClass"
                            File = $jar.Name
                            Entry = $entryName
                            Matched = $matches[0]
                        }
                    }
                }
            }
            $zip.Dispose()
        } catch {
            Write-Warning "Could not read JAR: $($jar.Name)"
        }
    }
    return $findings
}

function Scan-SystemArtifacts {
    Write-Host "Scanning system artifacts (self‑destruct evidence)..." -ForegroundColor Magenta
    $findings = @()
    if ($DeepScan) {
        # Prefetch
        if (Test-Path "$env:windir\Prefetch") {
            $prefetchFiles = Get-ChildItem -Path "$env:windir\Prefetch" -Filter "*.pf" -File -ErrorAction SilentlyContinue
            foreach ($pf in $prefetchFiles) {
                if ($pf.Name -match "javaw|minecraft|forge|fabric|cheat|hack|client") {
                    $findings += [PSCustomObject]@{
                        Category = "Prefetch"
                        File = $pf.Name
                        Path = $pf.FullName
                        LastWrite = $pf.LastWriteTimeUtc
                    }
                }
            }
        }
        # Recycle Bin
        $recyclePath = "C:`$Recycle.Bin"
        if (Test-Path $recyclePath) {
            $items = Get-ChildItem -Path $recyclePath -Recurse -File -ErrorAction SilentlyContinue
            foreach ($item in $items) {
                if ($item.Name -match "\.jar$|\.exe$|\.dll$") {
                    $findings += [PSCustomObject]@{
                        Category = "RecycleBin"
                        File = $item.Name
                        Path = $item.FullName
                        LastWrite = $item.LastWriteTimeUtc
                    }
                }
            }
        }
        # USN Journal (requires admin)
        try {
            $usnData = fsutil usn queryjournal C: 2>$null
            if ($LASTEXITCODE -eq 0) {
                $findings += [PSCustomObject]@{
                    Category = "USNJournal"
                    Info = "USN Journal available on C:"
                    Data = $usnData
                }
            }
        } catch { }
    } else {
        Write-Host "Skipping system artifact scan (use -DeepScan to enable)." -ForegroundColor Yellow
    }
    return $findings
}

#endregion

#region Scoring and Correlation

function Rate-Finding {
    param($Finding)
    $score = 0
    $severity = "Informational"
    $confidence = 50
    $categories = @($Finding.Category)
    $text = $Finding | Out-String
    foreach ($client in $Config.CheatClientAliases) {
        if ($text -match $client) {
            $score += 20
            $confidence = 70
        }
    }
    foreach ($module in $Config.ModuleIndicators) {
        if ($text -match $module) {
            if ($module -in $Config.WeakModules) {
                $score += 5
            } else {
                $score += 15
            }
            $confidence = 60
        }
    }
    if ($text -match "-javaagent|-agentpath|-Xbootclasspath|Instrumentation|URLClassLoader|defineClass|System.load") {
        $score += 30
        $confidence = 80
    }
    if ($text -match "Base64|AES|XOR|decrypt|decode|obfuscate") {
        $score += 10
        $confidence = 50
    }
    if ($categories.Count -gt 1) { $score += 10 }
    if ($score -ge 80) { $severity = "Critical" }
    elseif ($score -ge 60) { $severity = "High" }
    elseif ($score -ge 35) { $severity = "Medium" }
    elseif ($score -ge 15) { $severity = "Low" }
    else { $severity = "Informational" }

    return @{
        Severity = $severity
        Confidence = [math]::Min(100, $confidence + $score / 10)
        Score = $score
        Description = "Score: $score"
    }
}

#endregion

#region Report Generation

function Write-HtmlReport {
    param($Findings, $HashManifest, $SystemInfo)
    $html = @"
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>MagiciansReveal V3 – Forensic Report</title>
<style>
body { font-family: Arial, sans-serif; margin: 20px; }
h1 { color: #2c3e50; }
h2 { color: #34495e; border-bottom: 1px solid #ecf0f1; }
table { border-collapse: collapse; width: 100%; margin: 10px 0; }
th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
th { background-color: #f2f2f2; }
.section { margin: 20px 0; }
.disclaimer { background-color: #f9f9f9; padding: 15px; border-left: 4px solid #e74c3c; }
</style>
</head>
<body>
<h1>MagiciansReveal V3 – Minecraft Forensic Report</h1>
<p><strong>Tool:</strong> MagiciansReveal V3 (Tim$erz)</p>
<p><strong>Generated:</strong> $(Get-Date -Format "yyyy-MM-dd HH:mm:ss UTC")</p>
<p><strong>Host:</strong> $env:COMPUTERNAME</p>
<p><strong>User:</strong> $env:USERNAME</p>
<p><strong>PowerShell Version:</strong> $($PSVersionTable.PSVersion)</p>
<hr>
<div class="section">
<h2>Executive Summary</h2>
<p>This report contains findings from a forensic scan. All findings require analyst review.</p>
<p><strong>Total Findings:</strong> $($Findings.Count)</p>
</div>
<div class="section">
<h2>Findings</h2>
<table>
<tr><th>ID</th><th>Category</th><th>Severity</th><th>Confidence</th><th>File/Path</th><th>Indicator</th></tr>
$(
    $i=1
    foreach ($f in $Findings) {
        $id = "FIND-$i"
        $sev = $f.Severity
        $conf = $f.Confidence
        $cat = $f.Category
        $path = $f.Path
        $indicator = $f.Matched
        $color = if ($sev -eq 'Critical') { 'red' } elseif ($sev -eq 'High') { 'orange' } else { 'green' }
        "<tr><td>$id</td><td>$cat</td><td style='color:$color'>$sev</td><td>$conf</td><td>$path</td><td>$indicator</td></tr>"
        $i++
    }
)
</table>
</div>
<div class="section">
<h2>False Positives / Allowlisted Items</h2>
<p>The following known legitimate mods were excluded from high-severity scoring:</p>
<ul>$($Config.KnownLegitMods | ForEach-Object { "<li>$_</li>" })</ul>
</div>
<div class="disclaimer">
<strong>Disclaimer:</strong> This report is for investigative purposes only. Findings are indicators, not proof of wrongdoing. All findings require manual verification by an authorized analyst.
</div>
</body>
</html>
"@
    $htmlPath = Join-Path -Path $OutputPath -ChildPath "forensics-report.html"
    $html | Out-File -FilePath $htmlPath -Encoding UTF8
}

function Write-JsonReport {
    param($Findings)
    $jsonPath = Join-Path -Path $OutputPath -ChildPath "forensics-report.json"
    $Findings | ConvertTo-Json -Depth 5 | Out-File -FilePath $jsonPath -Encoding UTF8
}

function Write-CsvReport {
    param($Findings)
    $csvPath = Join-Path -Path $OutputPath -ChildPath "forensics-findings.csv"
    $Findings | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
}

function Write-TimelineCsv {
    param($Findings)
    $timelinePath = Join-Path -Path $OutputPath -ChildPath "forensics-timeline.csv"
    $Findings | Where-Object { $_.LastWrite } | Sort-Object LastWrite -Descending |
        Select-Object LastWrite, Category, File, Path, Severity |
        Export-Csv -Path $timelinePath -NoTypeInformation -Encoding UTF8
}

function Write-HashesCsv {
    param($Findings)
    $hashesPath = Join-Path -Path $OutputPath -ChildPath "forensics-hashes.csv"
    $Findings | Where-Object { $_.Hash } | Select-Object Path, Hash, File |
        Export-Csv -Path $hashesPath -NoTypeInformation -Encoding UTF8
}

function Write-SummaryText {
    param($Findings)
    $summaryPath = Join-Path -Path $OutputPath -ChildPath "forensics-summary.txt"
    $lines = @()
    $lines += "MagiciansReveal V3 – Minecraft Forensic Summary"
    $lines += "==============================================="
    $lines += "Tool: MagiciansReveal V3 (Tim`$erz)"
    $lines += "Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC')"
    $lines += "Host: $env:COMPUTERNAME"
    $lines += "User: $env:USERNAME"
    $lines += "Total Findings: $($Findings.Count)"
    $severities = $Findings | Group-Object Severity | ForEach-Object { "$($_.Name): $($_.Count)" }
    $lines += "Severity breakdown: $($severities -join ', ')"
    $lines += ""
    $lines += "High/Critical Findings:"
    $highCrit = $Findings | Where-Object { $_.Severity -in @('High','Critical') }
    foreach ($f in $highCrit) {
        $lines += "  [$($f.Severity)] $($f.Category) - $($f.File) : $($f.Matched)"
    }
    $lines | Out-File -FilePath $summaryPath -Encoding UTF8
}

#endregion

#region Console Display

function Show-ConsoleBanner {
    Clear-Host
    Write-Host @"
   ███╗   ███╗ █████╗  ██████╗ ██╗ ██████╗██╗ █████╗ ███╗   ██╗███████╗
   ████╗ ████║██╔══██╗██╔════╝ ██║██╔════╝██║██╔══██╗████╗  ██║██╔════╝
   ██╔████╔██║███████║██║  ███╗██║██║     ██║███████║██╔██╗ ██║███████╗
   ██║╚██╔╝██║██╔══██║██║   ██║██║██║     ██║██╔══██║██║╚██╗██║╚════██║
   ██║ ╚═╝ ██║██║  ██║╚██████╔╝██║╚██████╗██║██║  ██║██║ ╚████║███████║
   ╚═╝     ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚═╝ ╚═════╝╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝╚══════╝
"@ -ForegroundColor Cyan
    Write-Host "       ── 𝕸𝖆𝖌𝖎𝖈𝖎𝖆𝖓𝖘𝕽𝖊𝖛𝖊𝖆𝖑 𝖁3 ──" -ForegroundColor Magenta
    Write-Host "       Author: Tim`$erz    Version: 3.0.3" -ForegroundColor Gray
    Write-Host "       Read‑only forensic scanner for Minecraft anti‑cheat investigations." -ForegroundColor DarkGray
    Write-Host ""
}

function Show-DetailedFindings {
    param($Findings)
    if ($Findings.Count -eq 0) {
        Write-Host "`n✅ No suspicious findings detected." -ForegroundColor Green
        return
    }
    Write-Host "`n🔍 DETAILED FINDINGS" -ForegroundColor Cyan
    Write-Host "─────────────────────────────────────────────────────────────────" -ForegroundColor DarkGray
    foreach ($f in $Findings) {
        $color = if ($f.Severity -eq 'Critical') { 'Red' } elseif ($f.Severity -eq 'High') { 'Yellow' } elseif ($f.Severity -eq 'Medium') { 'Magenta' } else { 'Gray' }
        Write-Host "  [$($f.Severity)] " -NoNewline -ForegroundColor $color
        Write-Host "$($f.Category) " -NoNewline -ForegroundColor White
        Write-Host "- $($f.File) " -NoNewline -ForegroundColor Gray
        Write-Host "→ $($f.Matched)" -ForegroundColor Cyan
        if ($f.Path) {
            Write-Host "    Path: $($f.Path)" -ForegroundColor DarkGray
        }
        if ($f.Confidence) {
            Write-Host "    Confidence: $($f.Confidence)%" -ForegroundColor DarkGray
        }
        Write-Host ""
    }
}

function Ask-ReportGeneration {
    param($Findings)
    Write-Host "`n📄 Generate detailed report files? (y/n)" -ForegroundColor Yellow -NoNewline
    $response = Read-Host
    if ($response -eq 'y' -or $response -eq 'Y') {
        Write-Host "Generating reports in: $OutputPath" -ForegroundColor Green
        Write-HtmlReport -Findings $Findings -HashManifest $null -SystemInfo $null
        Write-JsonReport -Findings $Findings
        Write-CsvReport -Findings $Findings
        Write-TimelineCsv -Findings $Findings
        Write-HashesCsv -Findings $Findings
        Write-SummaryText -Findings $Findings
        Write-Host "Reports saved to: $OutputPath" -ForegroundColor Cyan
    } else {
        Write-Host "Skipping report file generation. Only console output displayed." -ForegroundColor Gray
    }
}

function Show-ConsoleSummary {
    param($Findings)
    $totalFindings = $Findings.Count
    $severityGroups = $Findings | Group-Object Severity
    $criticalCount = ($severityGroups | Where-Object { $_.Name -eq 'Critical' }).Count
    $highCount = ($severityGroups | Where-Object { $_.Name -eq 'High' }).Count
    $mediumCount = ($severityGroups | Where-Object { $_.Name -eq 'Medium' }).Count
    $lowCount = ($severityGroups | Where-Object { $_.Name -eq 'Low' }).Count
    $infoCount = ($severityGroups | Where-Object { $_.Name -eq 'Informational' }).Count

    Write-Host "`n╔══════════════════════════════════════════════════════════════════╗" -ForegroundColor DarkCyan
    Write-Host "║  " -NoNewline -ForegroundColor DarkCyan
    Write-Host "📊 SCAN SUMMARY" -ForegroundColor White
    Write-Host "║" -ForegroundColor DarkCyan
    Write-Host "║  Minecraft PID      : $($mcPid)" -ForegroundColor Gray
    Write-Host "║  Minecraft uptime   : $($uptime.Hours)h $($uptime.Minutes)m $($uptime.Seconds)s" -ForegroundColor Gray
    Write-Host "║  Total findings     : $totalFindings" -ForegroundColor Gray
    Write-Host "║  Critical           : $criticalCount" -ForegroundColor Red
    Write-Host "║  High               : $highCount" -ForegroundColor Yellow
    Write-Host "║  Medium             : $mediumCount" -ForegroundColor DarkYellow
    Write-Host "║  Low                : $lowCount" -ForegroundColor Green
    Write-Host "║  Informational      : $infoCount" -ForegroundColor DarkGray
    Write-Host "║" -ForegroundColor DarkCyan
    Write-Host "║  Output folder      : $OutputPath" -ForegroundColor DarkGray
    Write-Host "╚══════════════════════════════════════════════════════════════════╝" -ForegroundColor DarkCyan

    if ($criticalCount -gt 0 -or $highCount -gt 0) {
        Write-Host "`n🚨 HIGH/CRITICAL FINDINGS (highlighted)" -ForegroundColor Red
        Write-Host "─────────────────────────────────────────────────────────────────" -ForegroundColor DarkGray
        $highCrit = $Findings | Where-Object { $_.Severity -in @('High','Critical') }
        foreach ($f in $highCrit | Select-Object -First 10) {
            $color = if ($f.Severity -eq 'Critical') { 'Red' } else { 'Yellow' }
            Write-Host "  [$($f.Severity)] " -NoNewline -ForegroundColor $color
            Write-Host "$($f.Category) " -NoNewline -ForegroundColor White
            Write-Host "- $($f.File) " -NoNewline -ForegroundColor Gray
            Write-Host "→ $($f.Matched)" -ForegroundColor Cyan
        }
        if ($highCrit.Count -gt 10) {
            Write-Host "  ... and $($highCrit.Count - 10) more (see detailed list above)" -ForegroundColor Gray
        }
    }
}
#endregion

#region Main Execution

Show-ConsoleBanner

Write-Host "Minecraft process found: PID $mcPid (started $mcStart, uptime $($uptime.Hours)h $($uptime.Minutes)m $($uptime.Seconds)s)" -ForegroundColor Green
Write-Host ""

# Ask for the mods folder path
Write-Host "Enter the path to your Minecraft mods folder: " -NoNewline
$modsFolder = Read-Host
if ([string]::IsNullOrWhiteSpace($modsFolder)) {
    Write-Host "No folder provided. Exiting." -ForegroundColor Red
    exit 1
}
$modsFolder = Get-NormalizedPath -Path $modsFolder

Write-Host "Starting forensic scan..." -ForegroundColor Green

# Scan mods folder
$modFindings = Scan-ModsFolder -FolderPath $modsFolder

# Ask if user wants system scan (self-destruct)
Write-Host "`nDo you want to scan the entire system for self‑destruct evidence (Prefetch, Recycle Bin, USN Journal)? (y/n)" -ForegroundColor Yellow -NoNewline
$sysResponse = Read-Host
if ($sysResponse -eq 'y' -or $sysResponse -eq 'Y') {
    $DeepScan = $true
    $sysFindings = Scan-SystemArtifacts
} else {
    $sysFindings = @()
    Write-Host "Skipping system scan." -ForegroundColor Gray
}

$allFindings = $modFindings + $sysFindings

# Score all findings
$scoredFindings = @()
foreach ($f in $allFindings) {
    $rating = Rate-Finding -Finding $f
    $scoredFindings += [PSCustomObject]@{
        ID = "FIND-$([guid]::NewGuid().ToString().Substring(0,8))"
        Category = $f.Category
        File = $f.File
        Path = $f.Path
        Matched = if ($f.Matches) { ($f.Matches | Out-String) } else { $f.Matched }
        Severity = $rating.Severity
        Confidence = $rating.Confidence
        Score = $rating.Score
        LastWrite = $f.LastWrite
        Hash = $f.Hash
    }
}

# Display detailed findings
Show-DetailedFindings -Findings $scoredFindings

# Show summary with PID and options
Show-ConsoleSummary -Findings $scoredFindings

# Ask about report generation
Ask-ReportGeneration -Findings $scoredFindings

Write-Host "`n✅ Scan completed. Press any key to exit..." -ForegroundColor Green
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")

#endregion
