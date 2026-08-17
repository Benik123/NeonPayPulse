// Konfigurace pro snadnou změnu hodnot kdykoliv v budoucnu
const CONFIG = {
    standardUserShare: 0.50,
    boosterUserShare: 0.75,
    referralShare: 0.05,
    boosterPrice: 300
};

/**
 * Spočítá rozdělení odměny za zhlédnutí reklamy
 * @param {number} adRevenue - Celková odměna, kterou platí inzerent za reklamu (např. 10 Kč)
 * @param {boolean} hasBooster - Zda má uživatel aktivní booster
 * @param {boolean} hasReferral - Zda má uživatel nad sebou referala
 */
function calculateAdPayout(adRevenue, hasBooster, hasReferral) {
    // 1. Zjistíme podíl uživatele podle boosteru
    const userSharePercent = hasBooster ? CONFIG.boosterUserShare : CONFIG.standardUserShare;
    let userEarnings = adRevenue * userSharePercent;
    
    // Zbytek peněz jde zatím "majiteli" (ze kterého se případně platí referal)
    let ownerEarnings = adRevenue - userEarnings;
    
    let referralEarnings = 0;

    // 2. Pokud má uživatel referala, odečteme 5 % z celku (jde to z majitelova podílu)
    if (hasReferral) {
        referralEarnings = adRevenue * CONFIG.referralShare;
        ownerEarnings -= referralEarnings; // Majitel o tuto část přijde
    }

    return {
        totalAdRevenue: adRevenue,
        userGets: Number(userEarnings.toFixed(2)),
        ownerGets: Number(ownerEarnings.toFixed(2)),
        referralGets: Number(referralEarnings.toFixed(2))
    };
}

// --- TESTOVACÍ PKLAD ---
// Inzerent zaplatí za reklamu 10 Kč
console.log("--- 1. Free uživatel bez referala ---");
console.log(calculateAdPayout(10, false, false)); 
// Výsledek: Uživatel 5 Kč, Majitel 5 Kč, Referal 0 Kč

console.log("--- 2. Uživatel s Boosterem + má referala ---");
console.log(calculateAdPayout(10, true, true));  
// Výsledek: Uživatel 7.5 Kč, Majitel 2 Kč, Referal 0.5 Kč (celkem 10 Kč)