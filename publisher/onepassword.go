package publisher

import "github.com/rs/zerolog/log"

type OnePasswordItem struct {
	ID      string   `json:"id"`
	Title   string   `json:"title"`
	Tags    []string `json:"tags"`
	Version int      `json:"version"`
	Vault   struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	Category     string `json:"category"`
	LastEditedBy string `json:"last_edited_by"`
	CreatedAt    string `json:"created_at"`
	UpdatedAt    string `json:"updated_at"`
}

type OnePasswordValue struct {
	ID        string `json:"id"`
	Type      string `json:"type"`
	Label     string `json:"label"`
	Value     string `json:"value"`
	Reference string `json:"reference"`
}

func GetItemFromOnePassword() *OnePasswordItem {
	// Call out to the op CLI to avoid needing a service account for 1pass:
	cmdString := "op --account octoenergy.1password.com item list --tags terraform-tfc-token --format=json"
	var items []OnePasswordItem
	err := runCommandJSON(cmdString, &items)
	if err != nil {
		log.Error().Err(err).Msg("Error running op command")
	}
	if len(items) > 1 {
		log.Warn().Msg("Found more than one item with tag 'terraform-tfc-token', will use the first...")
	} else if len(items) < 1 {
		log.Warn().Msg("No items found with tag 'terraform-tfc-token'")
		return nil
	}
	item := items[0]
	log.Debug().Str("id", item.ID).Str("title", item.Title).Msg("Found item")
	return &item
}

func GetTokenFromOnePasswordItem(item *OnePasswordItem) string {
	// op item get --format=json --fields type=CONCEALED -
	cmdString := "op item get --format=json --fields type=CONCEALED " + item.ID
	var value OnePasswordValue
	err := runCommandJSON(cmdString, &value)
	if err != nil {
		log.Error().Err(err).Msg("Error running op command")
	}
	log.Debug().Str("id", value.ID).Str("ref", value.Reference).Msg("Found value")
	return value.Value
}

func ReadTokenFromOnePassword() string {
	item := GetItemFromOnePassword()
	if item == nil {
		return ""
	}
	token := GetTokenFromOnePasswordItem(item)
	return token
}
