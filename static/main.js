 // Fonction pour afficher ou cacher le formulaire de création de rubrique
 document.getElementById("show-create-rubrique-form").addEventListener("click", function() {
    var createRubriqueForm = document.getElementById("create-rubrique-form");
    if (createRubriqueForm.style.display === "none") {
        createRubriqueForm.style.display = "block";
    } else {
        createRubriqueForm.style.display = "none";
    }
});