from funcoes_google import *

def get_calendar_name_by_id(calendar_id: str, servico=servico, quota_emails=USER_EMAILS_FOR_QUOTA):
    """
    Busca e retorna o nome (summary) de um calendário específico pelo seu ID.

    Parâmetros:
        calendar_id (str): O ID do calendário a ser buscado.
        servico: A instância autenticada do serviço Google Calendar API.
        quota_emails (list[str]): A lista de e-mails para o rodízio de cotas.

    Retorna:
        str: O nome (summary) do calendário se encontrado.
        None: Se o calendário não for encontrado ou ocorrer um erro.
    """
    try:
        # 1. Seleciona um e-mail aleatório para o parâmetro quotaUser
        if not quota_emails:
            raise ValueError("A lista de e-mails para cota não pode estar vazia.")
        
        quota_user_email = random.choice(quota_emails)

        # 2. Faz uma chamada direta e eficiente à API para obter os dados do calendário
        calendar_data = servico.calendars().get(
            calendarId=calendar_id, 
            quotaUser=quota_user_email
        ).execute()

        # 3. Retorna o campo 'summary', que é o nome do calendário
        return calendar_data.get('summary')

    except HttpError as error:
        logger.error(f"Erro ao buscar o calendário com ID '{calendar_id}': {error}")
        return None
    except ValueError as e:
        logger.error(f"Erro na configuração da função: {e}")
        return None
    except Exception as e:
        logger.error(f"Um erro inesperado ocorreu ao buscar o nome do calendário: {e}")
        return None
    
calendar_ids = ["c_13a635c5d02bba21fcfd789c64204594a80d8d6d070f13b1e6dfa25d7fc90a7d@group.calendar.google.com",
"c_42ad7f1208f7209d05ccc5c92cf8cadf67535fc10a1f31d92bfdd50194502557@group.calendar.google.com",
"c_a67d5689f4bd90c6b76a5277b8cf1adffc9882cccfa663a71a67b995e8b95d32@group.calendar.google.com",
"c_7963cdff4c1ea65f4dfc82341f3d86c533fba74b9a5e767ec1a5c277bfa3ed8b@group.calendar.google.com",
"c_7a34fa778e9ddaed9e057b98809aec1387e98f15143aa283f41bfefb7a663d39@group.calendar.google.com",
"c_e5722c41a1dc5aa13fec1aef26ee182b79cc78fec103c4644ca3d418dae5cc63@group.calendar.google.com",
"c_8e1301394f750bc2f3bcf83ace5cdd49e6552c4f5dfd96cf3c99f4813b005568@group.calendar.google.com",
"c_d712e32d79fb956096f60af65cf0c000280fe6314974944082b6cdaa7a104e0d@group.calendar.google.com"]

def adicionar_calendarios_na_minha_lista(service, lista_ids):
    """
    Adiciona vários calendários à sua lista (caso você tenha permissão),
    usando calendarList.insert.

    Args:
        service: objeto autenticado da API Google Calendar.
        lista_ids: lista de IDs de calendários que você quer adicionar à sua conta.

    Returns:
        Uma lista de calendários adicionados com sucesso.
    """
    adicionados = []
    erros = []

    for calendar_id in lista_ids:
        print(f"📌 Tentando adicionar: {calendar_id}")
        try:
            result = service.calendarList().insert(body={"id": calendar_id}).execute()
            print(f"✅ Adicionado: {result.get('summary')} | ID: {result.get('id')}")
            adicionados.append(result.get('id'))
        except Exception as e:
            print(f"❌ Erro ao adicionar {calendar_id}: {e}")
            erros.append((calendar_id, str(e)))

    print(f"\n🎯 Total adicionados com sucesso: {len(adicionados)}")
    print(f"⚠️ Total com erro: {len(erros)}")

    return adicionados


print(get_calendar_name_by_id("c_7a34fa778e9ddaed9e057b98809aec1387e98f15143aa283f41bfefb7a663d39@group.calendar.google.com"))


