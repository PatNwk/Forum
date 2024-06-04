package main

import (
	"database/sql"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/gorilla/sessions"
)

var db *sql.DB
var store = sessions.NewCookieStore([]byte("your-secret-key"))

type User struct {
	ID          int
	Username    string
	Password    string
	Email       string
	Photo       []byte
	Gender      string
	Nationality string
	FirstName   string
	LastName    string
	CreatedAt   time.Time
	isAdmin     bool // Correction du nom du champ
}

type Rubrique struct {
	ID  int
	Nom string
}

type RubriquePageData struct {
	Messages  []Message
	Rubrique  Rubrique
	Rubriques []Rubrique
	Admin     bool // Ajouter le champ Admin
}

type Message struct {
	ID           int
	Titre        string
	Contenu      string
	DateCreation time.Time
	Auteur       string
	Gender       string
	Admin        bool
}

type UserRanking struct {
	Username     string
	MessageCount int
}

func indexHandler(w http.ResponseWriter, r *http.Request) {
	rubriqueID := r.FormValue("rubrique_id") // Récupérer l'ID de la rubrique depuis les paramètres de la requête

	var rows *sql.Rows
	var err error

	if rubriqueID != "" {
		// Si un ID de rubrique est spécifié, filtrer les messages par cette rubrique
		rows, err = db.Query("SELECT m.id, m.titre, m.contenu, m.date_creation, u.nom_utilisateur FROM Messages m JOIN Utilisateurs u ON m.auteur_id = u.id WHERE m.rubrique_id = ? ORDER BY m.date_creation DESC", rubriqueID)
	} else {
		// Sinon, récupérer tous les messages
		rows, err = db.Query("SELECT m.id, m.titre, m.contenu, m.date_creation, u.nom_utilisateur FROM Messages m JOIN Utilisateurs u ON m.auteur_id = u.id ORDER BY m.date_creation DESC")
	}

	if err != nil {
		http.Error(w, "Erreur lors de la récupération des messages: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var messages []Message

	for rows.Next() {
		var msg Message
		var dateCreationStr string
		err := rows.Scan(&msg.ID, &msg.Titre, &msg.Contenu, &dateCreationStr, &msg.Auteur)
		if err != nil {
			http.Error(w, "Erreur lors de la lecture des messages: "+err.Error(), http.StatusInternalServerError)
			return
		}
		msg.DateCreation, err = time.Parse("2006-01-02 15:04:05", dateCreationStr)
		if err != nil {
			http.Error(w, "Erreur lors de la conversion de la date: "+err.Error(), http.StatusInternalServerError)
			return
		}
		messages = append(messages, msg)
	}
	if err := rows.Err(); err != nil {
		http.Error(w, "Erreur lors de la lecture des messages: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Récupérer les rubriques depuis la base de données
	rubriques, err := getRubriques()
	if err != nil {
		http.Error(w, "Erreur lors de la récupération des rubriques: "+err.Error(), http.StatusInternalServerError)
		return
	}

	type PageData struct {
		Messages  []Message
		Rubriques []Rubrique
		Users     []User
	}

	data := PageData{
		Messages:  messages,
		Rubriques: rubriques,
	}

	tmpl, err := template.ParseFiles("templates/loggedin.html")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	err = tmpl.Execute(w, data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	// Récupérez le paramètre d'erreur de l'URL
	error := r.URL.Query().Get("error")

	// Affichez la page de connexion avec le message d'erreur
	tmpl, err := template.ParseFiles("templates/login.html")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	data := struct {
		Error string
	}{
		Error: error,
	}

	err = tmpl.Execute(w, data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func loginSubmitHandler(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	password := r.FormValue("password")

	query := "SELECT id FROM Utilisateurs WHERE nom_utilisateur = ? AND mot_de_passe = ?"
	var userID int
	err := db.QueryRow(query, username, password).Scan(&userID)
	if err != nil {
		// Rediriger avec le message d'erreur dans l'URL
		http.Redirect(w, r, "/login?error=invalid_credentials", http.StatusSeeOther)
		return
	}

	if userID != 0 {
		session, err := store.Get(r, "session-name")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		session.Values["authenticated"] = true
		session.Values["userID"] = userID

		err = session.Save(r, w)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, "/", http.StatusSeeOther)
	} else {
		// Rediriger avec le message d'erreur dans l'URL
		http.Redirect(w, r, "/login?error=invalid_credentials", http.StatusSeeOther)
	}
}

func registerHandler(w http.ResponseWriter, r *http.Request) {
	tmpl, err := template.ParseFiles("templates/register.html")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	data := struct {
		Error string
	}{
		r.URL.Query().Get("error"),
	}

	err = tmpl.Execute(w, data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func createUser(username, email, password, firstName, lastName, gender, nationality string) error {
	var count int
	err := db.QueryRow("SELECT COUNT(*) FROM Utilisateurs WHERE nom_utilisateur = ? OR email = ?", username, email).Scan(&count)
	if err != nil {
		return err
	}

	if count > 0 {
		return errors.New("invalid_credentials")
	}

	query := "INSERT INTO Utilisateurs (nom_utilisateur, mot_de_passe, email, first_name, last_name, gender, nationality) VALUES (?, ?, ?, ?, ?, ?, ?)"
	_, err = db.Exec(query, username, password, email, firstName, lastName, gender, nationality)
	if err != nil {
		return err
	}

	return nil
}

func registerSubmitHandler(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	email := r.FormValue("email")
	password := r.FormValue("password")
	firstName := r.FormValue("first_name")
	lastName := r.FormValue("last_name")
	gender := r.FormValue("gender")
	nationality := r.FormValue("nationality")

	err := createUser(username, email, password, firstName, lastName, gender, nationality)
	if err != nil {
		http.Redirect(w, r, "/register?error="+url.QueryEscape(err.Error()), http.StatusSeeOther)
		return
	}

	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func createMessageHandler(w http.ResponseWriter, r *http.Request) {
	session, err := store.Get(r, "session-name")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if auth, ok := session.Values["authenticated"].(bool); !ok || !auth {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	titre := r.FormValue("titre")
	contenu := r.FormValue("contenu")
	rubriqueID := r.FormValue("rubrique_id") // Récupérer l'ID de la rubrique depuis le formulaire
	userID := getCurrentUserID(r)
	if userID == 0 {
		http.Error(w, "Utilisateur non connecté", http.StatusUnauthorized)
		return
	}

	// Insérer le nouveau message dans la base de données en spécifiant la rubrique_id
	_, err = db.Exec("INSERT INTO Messages (titre, contenu, auteur_id, rubrique_id) VALUES (?, ?, ?, ?)", titre, contenu, userID, rubriqueID)
	if err != nil {
		http.Error(w, "Erreur lors de la création du message", http.StatusInternalServerError)
		return
	}

	// Rediriger l'utilisateur vers la page de la rubrique après la création du message
	http.Redirect(w, r, "/rubrique?id="+rubriqueID, http.StatusSeeOther)
}

func getCurrentUserID(r *http.Request) int {
	session, err := store.Get(r, "session-name")
	if err != nil {
		return 0
	}

	if auth, ok := session.Values["authenticated"].(bool); !ok || !auth {
		return 0
	}

	userID, ok := session.Values["userID"].(int)
	if !ok {
		return 0
	}

	return userID
}

func loggedInHandler(w http.ResponseWriter, r *http.Request) {
	userID := getCurrentUserID(r)
	if userID == 0 {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	// Note: UserData n'est pas utilisé dans cette fonction

	tmpl, err := template.ParseFiles("templates/loggedin.html")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	err = tmpl.Execute(w, nil) // Aucune donnée à passer au modèle pour le moment
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	session, err := store.Get(r, "session-name")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	delete(session.Values, "authenticated")
	delete(session.Values, "userID")

	err = session.Save(r, w)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func createRubriqueHandler(w http.ResponseWriter, r *http.Request) {

	userID := getCurrentUserID(r)
	if userID == 0 {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	nom := r.FormValue("nom")
	_, err := db.Exec("INSERT INTO Rubriques (nom) VALUES (?)", nom)
	if err != nil {
		http.Error(w, "Erreur lors de la création de la rubrique", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/", http.StatusSeeOther)

	// Vérifiez si l'utilisateur est administrateur
	isAdmin, err := checkAdminStatus(userID)
	if err != nil {
		http.Error(w, "Erreur lors de la vérification du statut de l'administrateur: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if !isAdmin {
		http.Error(w, "Vous n'avez pas les autorisations nécessaires pour accéder à cette fonctionnalité.", http.StatusUnauthorized)
		return
	}
}

func rubriqueHandler(w http.ResponseWriter, r *http.Request) {
	// Récupérer l'ID de la rubrique à partir des paramètres de la requête
	rubriqueID := r.FormValue("id")

	// Récupérer les messages de la rubrique depuis la base de données
	messages, err := getMessagesForRubrique(rubriqueID, getCurrentUserID(r))
	if err != nil {
		http.Error(w, "Erreur lors de la récupération des messages: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Récupérer les détails de la rubrique depuis la base de données
	rubrique, err := getRubriqueByID(rubriqueID)
	if err != nil {
		http.Error(w, "Erreur lors de la récupération des détails de la rubrique: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Récupérer toutes les rubriques
	rubriques, err := getRubriques()
	if err != nil {
		http.Error(w, "Erreur lors de la récupération des rubriques: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Vérifier le statut d'administrateur de l'utilisateur actuel
	userID := getCurrentUserID(r)
	isAdmin := false
	if userID != 0 {
		user, err := getUserByID(userID)
		if err != nil {
			http.Error(w, "Erreur lors de la récupération des données de l'utilisateur: "+err.Error(), http.StatusInternalServerError)
			return
		}
		isAdmin = user.isAdmin
	}

	// Analyser le modèle de page
	tmpl, err := template.ParseFiles("templates/rubrique.html")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Afficher la page avec les messages de la rubrique, les détails de la rubrique et le statut d'administrateur
	err = tmpl.Execute(w, RubriquePageData{
		Messages:  messages,
		Rubrique:  rubrique,
		Rubriques: rubriques,
		Admin:     isAdmin, // Passer le statut d'administrateur au modèle
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func getRubriques() ([]Rubrique, error) {
	rows, err := db.Query("SELECT id, nom FROM Rubriques")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var rubriques []Rubrique

	for rows.Next() {
		var rubrique Rubrique
		if err := rows.Scan(&rubrique.ID, &rubrique.Nom); err != nil {
			return nil, err
		}
		rubriques = append(rubriques, rubrique)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return rubriques, nil
}

func getMessagesForRubrique(rubriqueID string, userID int) ([]Message, error) {
	query := `
        SELECT m.id, m.titre, m.contenu, m.date_creation, u.nom_utilisateur, u.gender, u.isAdmin
        FROM Messages m 
        JOIN Utilisateurs u ON m.auteur_id = u.id 
        WHERE m.rubrique_id = ?`

	rows, err := db.Query(query, rubriqueID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var messages []Message

	for rows.Next() {
		var msg Message
		var dateCreationStr string
		err := rows.Scan(&msg.ID, &msg.Titre, &msg.Contenu, &dateCreationStr, &msg.Auteur, &msg.Gender, &msg.Admin)
		if err != nil {
			return nil, err
		}
		msg.DateCreation, err = time.Parse("2006-01-02 15:04:05", dateCreationStr)
		if err != nil {
			return nil, err
		}
		messages = append(messages, msg)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return messages, nil
}

func getRubriqueByID(rubriqueID string) (Rubrique, error) {
	var rubrique Rubrique

	// Exemple de requête SQL pour récupérer les détails d'une rubrique spécifique
	query := "SELECT id, nom FROM Rubriques WHERE id = ?"

	// Exécute la requête SQL en utilisant l'identifiant de la rubrique spécifiée
	err := db.QueryRow(query, rubriqueID).Scan(&rubrique.ID, &rubrique.Nom)
	if err != nil {
		return Rubrique{}, err
	}

	return rubrique, nil
}
func hideMessageHandler(w http.ResponseWriter, r *http.Request) {
	// Vérifier si l'utilisateur est connecté
	userID := getCurrentUserID(r)
	if userID == 0 {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	// Vérifier si l'utilisateur est un administrateur
	isAdmin, err := checkAdminStatus(userID)
	if err != nil {
		http.Error(w, "Erreur lors de la vérification du statut de l'administrateur: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if !isAdmin {
		http.Error(w, "Vous n'avez pas les autorisations nécessaires pour masquer ce message.", http.StatusUnauthorized)
		return
	}

	// Récupérer l'ID du message à masquer depuis les paramètres de la requête
	messageID := r.FormValue("message_id")

	// Masquer le message dans la base de données
	err = hideMessage(messageID)
	if err != nil {
		http.Error(w, "Erreur lors du masquage du message: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Rediriger l'utilisateur vers la page où le message était affiché
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func checkAdminStatus(userID int) (bool, error) {
	var isAdmin bool
	err := db.QueryRow("SELECT isAdmin FROM Utilisateurs WHERE id = ?", userID).Scan(&isAdmin)
	if err != nil {
		return false, err
	}
	return isAdmin, nil
}

func hideMessage(messageID string) error {
	// Masquer le message dans la base de données en définissant un champ "hidden" à true
	_, err := db.Exec("UPDATE Messages SET hidden = true WHERE id = ?", messageID)
	if err != nil {
		return err
	}
	return nil
}

// profileHandler affiche la page du profil utilisateur
func profileHandler(w http.ResponseWriter, r *http.Request) {
	userID := getCurrentUserID(r)
	if userID == 0 {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	user, err := getUserByID(userID)
	if err != nil {
		http.Error(w, "Erreur lors de la récupération des données de l'utilisateur: "+err.Error(), http.StatusInternalServerError)
		return
	}

	tmpl, err := template.ParseFiles("templates/profile.html")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	err = tmpl.Execute(w, user)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func userRankingHandler(w http.ResponseWriter, r *http.Request) {
	users, err := getUsersByMessageCount()
	if err != nil {
		http.Error(w, "Erreur lors de la récupération du classement des utilisateurs: "+err.Error(), http.StatusInternalServerError)
		return
	}

	tmpl, err := template.ParseFiles("templates/user_ranking.html") // Créez un modèle spécifique pour le classement des utilisateurs
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Préparer les données à transmettre au modèle
	var data struct {
		Users []UserRanking
	}
	data.Users = users

	err = tmpl.Execute(w, data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func getUsersByMessageCount() ([]UserRanking, error) {
	query := `
        SELECT u.nom_utilisateur, COUNT(m.id) AS message_count
        FROM Utilisateurs u
        LEFT JOIN Messages m ON u.id = m.auteur_id
        GROUP BY u.nom_utilisateur
        ORDER BY message_count DESC
    `

	rows, err := db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []UserRanking

	for rows.Next() {
		var user UserRanking
		err := rows.Scan(&user.Username, &user.MessageCount)
		if err != nil {
			return nil, err
		}
		users = append(users, user)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return users, nil
}

func getUserByID(userID int) (User, error) {
	var user User

	query := "SELECT id, nom_utilisateur, email, photo_profil, gender, nationality, first_name, last_name, created_at, isAdmin FROM Utilisateurs WHERE id = ?"

	var createdAtStr string
	err := db.QueryRow(query, userID).Scan(&user.ID, &user.Username, &user.Email, &user.Photo, &user.Gender, &user.Nationality, &user.FirstName, &user.LastName, &createdAtStr, &user.isAdmin)
	if err != nil {
		return User{}, err
	}

	createdAt, err := time.Parse("2006-01-02 15:04:05", createdAtStr)
	if err != nil {
		return User{}, err
	}

	user.CreatedAt = createdAt

	return user, nil
}

func main() {
	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

	var err error
	db, err = sql.Open("mysql", "root:patryk06@tcp(127.0.0.1:3306)/sys")
	if err != nil {
		panic(err.Error())
	}
	defer db.Close()

	http.HandleFunc("/", indexHandler)
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/login-submit", loginSubmitHandler)
	http.HandleFunc("/register", registerHandler)
	http.HandleFunc("/register-submit", registerSubmitHandler)
	http.HandleFunc("/create-message", createMessageHandler)
	http.HandleFunc("/loggedin", loggedInHandler)
	http.HandleFunc("/create-rubrique", createRubriqueHandler)
	http.HandleFunc("/rubrique", rubriqueHandler)
	http.HandleFunc("/profile", profileHandler)
	http.HandleFunc("/hide-message", hideMessageHandler)
	http.HandleFunc("/user-ranking", userRankingHandler)

	http.HandleFunc("/logout", logoutHandler)

	fmt.Println("Serveur démarré sur le port 8080...")
	err = http.ListenAndServe(":8000", nil)
	if err != nil {
		panic(err.Error())
	}
}
