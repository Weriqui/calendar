from __future__ import print_function
import time
import os
from typing import List, Optional
from googleapiclient.http import BatchHttpRequest
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request
from google_auth_oauthlib.flow import InstalledAppFlow
from google.oauth2 import service_account
from googleapiclient.errors import HttpError
from googleapiclient.discovery import build
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type, wait_random_exponential, retry_if_exception
import requests
import random
import json
import ssl
from functools import partial
import logging

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Formatação dos logs
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

# Handler para salvar em arquivo
file_handler = logging.FileHandler('funcoes_google.log')
file_handler.setFormatter(formatter)

# Handler para exibir no terminal
console_handler = logging.StreamHandler()
console_handler.setFormatter(formatter)

# Adiciona os handlers ao logger
logger.addHandler(file_handler)
logger.addHandler(console_handler)

SCOPES: List[str] = ["https://www.googleapis.com/auth/calendar"]
SERVICE_ACCOUNT_FILE = json.loads(os.environ.get("SERVICE_ACCOUNT_FILE"))
USER_TO_IMPERSONATE = os.environ.get("USER_TO_IMPERSONATE")
DEFAULT_TIMEZONE = "America/Sao_Paulo"



credentials = service_account.Credentials.from_service_account_info(
    SERVICE_ACCOUNT_FILE,
    scopes=SCOPES,
    subject=USER_TO_IMPERSONATE
)

servico = build('calendar', 'v3', credentials=credentials)


def criar_calendario(nome: str,servico: service_account = servico,time_zone: str = "America/Sao_Paulo") -> str:
    body = {"summary": nome, "timeZone": time_zone}
    calendar = servico.calendars().insert(body=body).execute()

    calendar_id = calendar["id"]
    print(f"Calendário “{nome}” criado! ID: {calendar_id}")
    return calendar_id

def create_calendars_batch(names_list: list[str], time_zone: str = DEFAULT_TIMEZONE, servico=servico) -> tuple[dict, dict]:
    """
    Prepara e executa a criação de múltiplos calendários em lote,
    utilizando a função _execute_operations_with_item_retry existente.

    NOTA: Devido às limitações da função de execução não modificada,
          esta função reporta sucesso/falha por nome, mas NÃO retorna os IDs
          dos calendários criados.

    Parâmetros:
        names_list: Lista com os nomes (summary) dos calendários.
        servico: Instância autenticada do serviço Google Calendar API v3.
        time_zone: Fuso horário para os novos calendários.

    Retorna:
        Uma tupla contendo:
        - dict: Dicionário de resultados {nome_original: {'status': 'success'|'failed', 'message': '...'}}.
        - dict: Dicionário consolidado de erros {request_id: error_message}.
    """
    if not names_list:
        return {}, {"input_error": "A lista de nomes não pode estar vazia."}

    operations_to_execute = []
    initial_errors = {}
    # Usaremos este mapa para construir o resultado final
    operation_details_map = {} # {op_key: {'request_id':..., 'original_name':...}}

    start_prep_time = time.time()
    logger.info(f"Preparing batch calendar creation for {len(names_list)} names.")

    for index, name in enumerate(names_list):
        name = name.strip()
        op_key = f"{index}-{name}" # Chave única para o mapa interno
        request_id = op_key # ID para o batch

        # Guarda detalhes para referência posterior
        operation_details_map[op_key] = {"request_id": request_id, "original_name": name}

        if not name:
            logger.warning(f"Skipping empty calendar name at index {index}.")
            initial_errors[request_id] = "Nome vazio fornecido."
            continue # Pula para o próximo nome, não adiciona à execução

        calendar_body = {
            "summary": name,
            "timeZone": time_zone
        }

        try:
            api_call_func = partial(servico.calendars().insert, body=calendar_body)
            operations_to_execute.append({
                "request_id": request_id,
                "op_key": op_key,
                # "original_name": name, # Não precisamos mais passar daqui pra frente
                "api_call_func": api_call_func
            })
        except Exception as prep_err:
             logger.error(f"Error preparing operation for calendar name '{name}': {prep_err}", exc_info=True)
             initial_errors[request_id] = f"Erro na preparação: {prep_err}"

    prep_time = time.time() - start_prep_time
    logger.info(f"Preparation finished in {prep_time:.2f}s. {len(operations_to_execute)} operations queued.")

    # Chama a função de execução existente
    final_results_map = {} # {nome_original: {'status': ..., 'message': ...}}
    batch_run_success_results = {} # {op_key: message_string}
    batch_run_final_errors = {} # {request_id: error_message}

    if operations_to_execute:
        logger.info(f"Calling _execute_operations_with_item_retry for {len(operations_to_execute)} calendar creations.")
        try:
            # Chama a função *existente*. Passa um action_name para o log/callback.
            # O callback interno vai gerar mensagens como "Operação concluída." para sucessos.
            batch_run_success_results, batch_run_final_errors = _execute_operations_with_item_retry(
                operations=operations_to_execute,
                action_name="create_calendar", # Nome descritivo
                max_retries=MAX_ITEM_RETRIES,
                servico=servico
            )
            logger.info("Returned from _execute_operations_with_item_retry.")

        except Exception as exec_critical_err:
             logger.error(f"CRITICAL ERROR during batch execution call: {exec_critical_err}", exc_info=True)
             initial_errors["__execution_critical__"] = f"Erro crítico na execução: {exec_critical_err}"
             # Marca todos como falha se a execução inteira falhou
             for op_key, op_detail in operation_details_map.items():
                  if op_detail["request_id"] not in initial_errors: # Só marca se não falhou na preparação
                       final_results_map[op_detail["original_name"]] = {'status': 'failed', 'message': f"Falha crítica no batch: {exec_critical_err}"}


    else:
        logger.info("No valid calendar creation operations to execute.")

    # Processa os resultados retornados pela função de execução não modificada
    logger.info("Processing results from batch execution...")
    # Junta os erros finais do batch run com os erros iniciais
    final_consolidated_errors = initial_errors.copy()
    final_consolidated_errors.update(batch_run_final_errors)

    # Constrói o mapa de resultados final
    for op_key, op_detail in operation_details_map.items():
        request_id = op_detail["request_id"]
        original_name = op_detail["original_name"]

        # Se já existe no mapa final (ex: falha na preparação), não sobrescreve
        if original_name in final_results_map:
             continue

        # Verifica se teve sucesso na execução
        if op_key in batch_run_success_results:
            # Sucesso! Mensagem será genérica vinda do callback atual.
            success_msg = batch_run_success_results[op_key]
            # Não temos o ID do calendário aqui!
            final_results_map[original_name] = {'status': 'success', 'message': success_msg}
        # Verifica se teve erro final na execução
        elif request_id in batch_run_final_errors:
            final_results_map[original_name] = {'status': 'failed', 'message': batch_run_final_errors[request_id]}
        # Verifica se teve erro inicial (ex: nome vazio)
        elif request_id in initial_errors:
             final_results_map[original_name] = {'status': 'failed', 'message': initial_errors[request_id]}
        else:
             # Não deveria acontecer se a operação foi para execução
             logger.error(f"Operation {op_key} ({original_name}) has no final status recorded.")
             final_results_map[original_name] = {'status': 'unknown', 'message': 'Status final desconhecido.'}


    logger.info("Finished batch calendar creation process.")
    # Retorna o mapa de resultados por nome e os erros consolidados
    return final_results_map, final_consolidated_errors


def renomear_calendario(calendar_id: str,novo_nome: str,servico=servico) -> None:
    body = {"summary": novo_nome}

    # PATCH altera apenas os campos enviados
    servico.calendars().patch(calendarId=calendar_id,body=body).execute()

    print(f'Calendário {calendar_id} renomeado para “{novo_nome}”.')


def calendarios(servico=servico):
    """
    Retorna a lista de calendários disponíveis na conta.
    """
    try:
        nao = ["pipedrive@villeladigital.com.br","Feriados no Brasil"]
        calendars = servico.calendarList().list().execute()
        calendarios_para_retornar = [i for i in calendars["items"] if not i["summary"] in nao]
        return calendarios_para_retornar
    except HttpError as error:
        print(f"Erro ao listar calendários: {error}")
        return []

def listar_usuarios_calendario(calendar_id, servico=servico):
    """
    Lista todos os usuários com acesso a um calendário específico e seus níveis de acesso.

    Parâmetros:
    - calendar_id: ID do calendário a ser verificado.
    - servico: Instância do serviço do Google Calendar.

    Retorna:
    - Uma lista de dicionários contendo o e-mail (ou valor) e o nível de acesso ('role').
    """
    try:
        # Obtém a lista de regras de acesso (ACL) para o calendário especificado.
        acl = servico.acl().list(calendarId=calendar_id).execute()
        usuarios = []
        for regra in acl.get("items", []):
            # Considera apenas os escopos do tipo 'user'.
            if regra.get("scope", {}).get("type") == "user":
                potential_email = regra["scope"].get("value")
                is_system_id = (
                    potential_email.endswith('@group.calendar.google.com') or
                    potential_email.endswith('@resource.calendar.google.com')
                    # Adicione aqui outros padrões se souber de mais algum, ex:
                    # potential_email.endswith('.gserviceaccount.com') # Se contas de serviço aparecerem como 'user'
                )
                if not is_system_id:
                    usuario_info = {
                        "email": regra["scope"].get("value"),
                        "role": regra.get("role")
                    }
                    usuarios.append(usuario_info)
        return usuarios
    except HttpError as error:
        print(f"Erro ao listar usuários do calendário {calendar_id}: {error}")
        return []

def listar_calendarios_usuario(user_email, servico=servico):
    """
    Lista todos os calendários aos quais um usuário possui acesso, incluindo o nível de acesso em cada um.

    Parâmetros:
    - user_email: E-mail do usuário a ser verificado.
    - servico: Instância do serviço do Google Calendar.

    Retorna:
    - Uma lista de dicionários com os dados do calendário e o nível de acesso do usuário.
    """
    calendarios_usuario = []
    try:
        # Obtém todos os calendários da conta.
        todos_calendarios = calendarios(servico)
        # Percorre cada calendário para verificar se o usuário possui alguma regra de acesso.
        for cal in todos_calendarios:
            calendar_id = cal["id"]
            try:
                acl = servico.acl().list(calendarId=calendar_id).execute()
                # Procura uma regra cujo escopo seja do tipo 'user' e cujo valor seja o email informado.
                for regra in acl.get("items", []):
                    scope = regra.get("scope", {})
                    if scope.get("type") == "user" and scope.get("value") == user_email:
                        calendarios_usuario.append({
                            "calendar_id": calendar_id,
                            "summary": cal.get("summary"),
                            "role": regra.get("role")
                        })
                        break  # Se encontrar, não precisa iterar nas demais regras
            except HttpError as error:
                print(f"Erro ao acessar ACL do calendário {calendar_id}: {error}")
        return calendarios_usuario
    except HttpError as error:
        print(f"Erro ao listar calendários: {error}")
        return []

def modificar_acesso_usuarios(calendario_ids, user_emails, acao, role='writer', servico=servico):
    """
    Adiciona, remove ou edita os níveis de acesso de um ou mais usuários em um ou mais calendários.

    Parâmetros:
    - calendario_ids: Lista com os IDs dos calendários a serem modificados.
    - user_emails: Lista com os e-mails dos usuários a serem modificados.
    - acao: Ação a ser realizada: 'adicionar', 'remover' ou 'editar'.
    - role: Nível de acesso (ex: 'owner', 'writer', 'reader'). Necessário para 'adicionar' ou 'editar'.
    - servico: Instância do serviço do Google Calendar.

    Retorna:
    - Um dicionário com os resultados das operações para cada calendário e usuário.
    """
    resultados = {}
    
    for calendar_id in calendario_ids:
        resultados[calendar_id] = {}
        for user_email in user_emails:
            try:
                if acao == "adicionar":
                    # Cria um novo ACL para o usuário no calendário
                    regra = {
                        "scope": {
                            "type": "user",
                            "value": user_email
                        },
                        "role": role
                    }
                    resposta = servico.acl().insert(calendarId=calendar_id, body=regra).execute()
                    resultados[calendar_id][user_email] = f"Acesso adicionado: {resposta.get('role')}"
                elif acao == "editar":
                    # Primeiro, obtém a regra existente para o usuário
                    acl = servico.acl().list(calendarId=calendar_id).execute()
                    regra_id = None
                    for regra in acl.get("items", []):
                        scope = regra.get("scope", {})
                        if scope.get("type") == "user" and scope.get("value") == user_email:
                            regra_id = regra.get("id")
                            break
                    if regra_id:
                        # Atualiza a regra com o novo nível de acesso
                        nova_regra = {
                            "role": role,
                            "scope": {
                                "type": "user",
                                "value": user_email
                            }
                        }
                        resposta = servico.acl().update(calendarId=calendar_id, ruleId=regra_id, body=nova_regra).execute()
                        resultados[calendar_id][user_email] = f"Acesso atualizado para: {resposta.get('role')}"
                    else:
                        resultados[calendar_id][user_email] = "Regra de acesso não encontrada para edição."
                elif acao == "remover":
                    # Primeiro, obtém a regra existente para o usuário
                    acl = servico.acl().list(calendarId=calendar_id).execute()
                    regra_id = None
                    for regra in acl.get("items", []):
                        scope = regra.get("scope", {})
                        if scope.get("type") == "user" and scope.get("value") == user_email:
                            regra_id = regra.get("id")
                            break
                    if regra_id:
                        servico.acl().delete(calendarId=calendar_id, ruleId=regra_id).execute()
                        resultados[calendar_id][user_email] = "Acesso removido com sucesso."
                    else:
                        resultados[calendar_id][user_email] = "Regra de acesso não encontrada para remoção."
                else:
                    resultados[calendar_id][user_email] = "Ação inválida. Use 'adicionar', 'editar' ou 'remover'."
            except HttpError as error:
                resultados[calendar_id][user_email] = f"Erro ao modificar acesso: {error}"
    
    return resultados


def remover_acesso_todos_calendarios(user_email, servico=servico):
    """
    Remove o acesso de um usuário a todas as agendas onde ele possui permissão.

    Parâmetros:
    - user_email: E-mail do usuário cujo acesso será removido.
    - servico: Instância do serviço do Google Calendar.

    Retorna:
    - Um dicionário com os resultados da operação para cada calendário.
      A chave é o ID do calendário e o valor é uma mensagem informando se o acesso
      foi removido com sucesso, se não foi encontrado ou se houve algum erro.
    """
    resultados = {}
    # Obtém a lista de calendários em que o usuário tem acesso
    calendarios_usuario = listar_calendarios_usuario(user_email, servico)
    
    # Itera por cada calendário para remover a regra de acesso
    for calendario in calendarios_usuario:
        calendar_id = calendario["calendar_id"]
        try:
            # Obtém a ACL atual do calendário
            acl = servico.acl().list(calendarId=calendar_id).execute()
            rule_id = None
            # Procura a regra que corresponda ao usuário
            for regra in acl.get("items", []):
                scope = regra.get("scope", {})
                if scope.get("type") == "user" and scope.get("value") == user_email:
                    rule_id = regra.get("id")
                    break
            # Se a regra for encontrada, realiza a remoção
            if rule_id:
                servico.acl().delete(calendarId=calendar_id, ruleId=rule_id).execute()
                resultados[calendar_id] = f"Acesso removido com sucesso para {user_email}."
            else:
                resultados[calendar_id] = f"Regra de acesso não encontrada para {user_email}."
        except HttpError as error:
            resultados[calendar_id] = f"Erro ao remover acesso: {error}"
    
    return resultados




def get_acl_users_batch(calendar_ids: list, servico=servico) -> tuple[list, dict]:
    """
    Busca as ACLs de múltiplos calendários usando Batch Request.

    Parâmetros:
        calendar_ids: Lista de IDs dos calendários.
        servico: Instância autenticada do serviço Google Calendar API v3.

    Retorna:
        Uma tupla contendo:
        - list: Lista de dicionários de usuários únicos no formato [{"value": email, "label": email}].
        - dict: Dicionário de erros ocorridos {calendar_id: error_message}.
    """
    if not calendar_ids:
        return [], {}

    # Dicionários para armazenar resultados e erros durante o processamento do batch
    unique_users_map = {} # Usaremos um mapa para fácil checagem de duplicatas {email: role}
    batch_errors = {}     # {calendar_id: error_message}

    start_total_time = time.time()
    logger.info(f"Starting batch processing for {len(calendar_ids)} calendars.")

    # Define a função de callback INTERNA a esta função
    def process_acl_list_response(request_id, response, exception):
        """Callback para processar cada resposta individual do batch."""
        calendar_id = request_id # Recupera o ID do calendário

        if exception:
            error_message = str(exception)
            status_code = getattr(exception, 'resp', {}).get('status', 'N/A')
            logger.error(f"Error processing calendar {calendar_id} in batch (Status: {status_code}): {error_message}")
            batch_errors[calendar_id] = f"Status {status_code}: {error_message}"
        else:
            logger.debug(f"Processing successful response for calendar {calendar_id}")
            users_added_from_this = 0
            for regra in response.get("items", []):
                scope = regra.get("scope", {})
                scope_type = scope.get("type")
                scope_value = scope.get("value")

                # Verifica se é um usuário real e não um ID de calendário/grupo
                # Condição 1: Tipo deve ser 'user' (conforme retornado pela API)
                # Condição 2: Deve ter um valor
                # Condição 3: Valor deve conter '@' (verificação básica de formato)
                if scope_type == "user" and scope_value and '@' in scope_value:
                    potential_email = scope_value

                    # Condição 4: VERIFICA SE NÃO É UM ID DE SISTEMA CONHECIDO
                    is_system_id = (
                        potential_email.endswith('@group.calendar.google.com') or
                        potential_email.endswith('@resource.calendar.google.com')
                        # Adicione aqui outros padrões se souber de mais algum, ex:
                        # potential_email.endswith('.gserviceaccount.com') # Se contas de serviço aparecerem como 'user'
                    )

                    # Adiciona APENAS se NÃO for um ID de sistema E ainda não estiver na lista
                    if not is_system_id and potential_email not in unique_users_map:
                        unique_users_map[potential_email] = regra.get("role", "reader")
                        users_added_from_this += 1
                        logger.debug(f"Added user: {potential_email} from {calendar_id}")
                    elif is_system_id:
                        # Apenas loga que pulou um ID de sistema (opcional)
                        logger.debug(f"Skipping system ID found in ACL: {potential_email} from {calendar_id}")
            if users_added_from_this > 0:
                 logger.debug(f"Added {users_added_from_this} unique users from {calendar_id}.")
            if not response.get("items"):
                 logger.debug(f"No user ACLs found for {calendar_id}.")


    # Cria o objeto BatchHttpRequest
    batch = servico.new_batch_http_request(callback=process_acl_list_response)

    # Adiciona as requisições ao batch
    logger.info(f"Building batch request...")
    calendars_added_to_batch = 0
    for cal_id in calendar_ids:
        if not isinstance(cal_id, str) or '@' not in cal_id:
             logger.warning(f"Skipping invalid calendar ID format: {cal_id}")
             batch_errors[str(cal_id)] = "Invalid ID format (skipped)"
             continue
        try:
            batch.add(servico.acl().list(calendarId=cal_id), request_id=cal_id)
            calendars_added_to_batch += 1
        except Exception as e:
            logger.error(f"Failed to add calendar {cal_id} to batch object: {e}")
            batch_errors[cal_id] = f"Failed to add to batch: {str(e)}"

    if calendars_added_to_batch == 0:
         logger.warning("No valid calendars were added to the batch.")
         return [], batch_errors # Retorna erros acumulados se houver

    # Executa o batch
    try:
        logger.info(f"Executing batch request for {calendars_added_to_batch} calendars...")
        start_exec_time = time.time()
        # Considere adicionar retentativas com tenacity aqui em torno do execute()
        batch.execute()
        end_exec_time = time.time()
        logger.info(f"Batch execution finished in {end_exec_time - start_exec_time:.2f} seconds.")

    except HttpError as e:
        logger.error(f"Fatal HTTP error during batch execution: {e}", exc_info=True)
        # Retorna um erro geral indicando que o batch falhou
        # Mantém os erros individuais que podem ter sido registrados antes da falha fatal
        batch_errors["__batch_execution_error__"] = f"HTTP Error: {str(e)}"
        # A lista de usuários pode estar incompleta ou vazia
    except Exception as e:
        logger.error(f"Fatal unexpected error during batch execution: {e}", exc_info=True)
        batch_errors["__batch_execution_error__"] = f"Unexpected Error: {str(e)}"

    # Formata a lista final de usuários únicos
    users_output_list = [{"value": email, "label": email} for email in unique_users_map.keys()]

    end_total_time = time.time()
    logger.info(f"Batch processing complete in {end_total_time - start_total_time:.2f} seconds. Found {len(users_output_list)} unique users.")
    if batch_errors:
        logger.warning(f"Finished with {len(batch_errors)} errors for individual calendars or the batch itself.")

    return users_output_list, batch_errors

REQUEST_ID_SEPARATOR = '||'
MAX_ITEM_RETRIES = 10

def modify_acl_users_batch(calendar_ids: list, user_emails: list, action: str, role: str, servico=servico) -> tuple[dict, dict]:
    """
    Adiciona, remove ou edita ACLs para múltiplos usuários em múltiplos calendários usando Batch Requests.

    Parâmetros:
        calendar_ids: Lista de IDs dos calendários.
        user_emails: Lista de e-mails dos usuários.
        action: Ação ('adicionar', 'remover', 'editar').
        role: Nível de acesso ('owner', 'writer', 'reader', etc.). Necessário para 'adicionar' e 'editar'.
        servico: Instância autenticada do serviço Google Calendar API v3.

    Retorna:
        Uma tupla contendo:
        - dict: Dicionário de resultados {calendar_id: {user_email: message}}.
        - dict: Dicionário de erros gerais ou do batch {key: error_message}.
    """
    if not all([calendar_ids, user_emails, action]):
        return {}, {"input_error": "calendar_ids, user_emails e action são obrigatórios."}
    if action in ['adicionar', 'editar'] and not role:
        return {}, {"input_error": "O parâmetro 'role' é obrigatório para as ações 'adicionar' e 'editar'."}
    if action not in ['adicionar', 'remover', 'editar']:
        return {}, {"input_error": f"Ação '{action}' inválida. Use 'adicionar', 'remover' ou 'editar'."}

    # Estruturas para guardar resultados e erros
    # Usamos listas para erros de batch para poder anexar de diferentes fases
    results = {cal_id: {} for cal_id in calendar_ids}

    start_prep_time = time.time()
    logger.info(f"Preparing batch modification. Action: '{action}', Calendars: {len(calendar_ids)}, Users: {len(user_emails)}")

    # Lista para guardar as operações a serem executadas pelo batch com retry
    operations_to_execute = []
    # Dicionário para guardar resultados de operações que falham *antes* do batch (ex: rule_id não encontrado)
    initial_results = {cal_id: {} for cal_id in calendar_ids}
    initial_errors = {} # Erros que ocorrem nesta fase de preparação

    # --- Lógica para 'adicionar' ---
    if action == 'adicionar':
        for cal_id in calendar_ids:
            for user_email in user_emails:
                # Validação básica do email
                if not isinstance(user_email, str) or '@' not in user_email:
                    results[cal_id][user_email] = "Formato de e-mail inválido."
                    logger.warning(f"Skipping invalid email format: {user_email} for calendar {cal_id}")
                    continue

                regra_body = {
                    "scope": {"type": "user", "value": user_email},
                    "role": role
                }
                request_id = f"{cal_id}{REQUEST_ID_SEPARATOR}{user_email}"
                operations_to_execute.append({
                    "request_id": request_id,
                    "op_key": (cal_id, user_email),
                    "api_call_func": partial(servico.acl().insert, calendarId=cal_id, body=regra_body)
                })

    # --- Lógica para 'editar' ou 'remover' ---
    elif action in ['editar', 'remover']:
        # ** FASE 1: Obter Rule IDs **
        logger.info(f"Starting Phase 1 for '{action}': Listing ACLs to find rule IDs...")
        rule_map = {} # {(calendar_id, user_email): rule_id}
        list_errors = [] # Erros específicos da fase de listagem

        # Callback para processar as respostas do acl().list
        def process_list_callback(request_id, response, exception):
            calendar_id = request_id # Aqui o request_id é só o calendar_id
            if exception:
                error_message = str(exception)
                status_code = getattr(exception, 'resp', {}).get('status', 'N/A')
                logger.error(f"Phase 1 Error listing ACL for {calendar_id} (Status: {status_code}): {error_message}")
                # Guarda o erro associado ao calendário para possível reporte
                list_errors.append({calendar_id: f"List ACL Error (Status {status_code}): {error_message}"})
            else:
                logger.debug(f"Phase 1 Processing list response for {calendar_id}")
                for regra in response.get("items", []):
                    scope = regra.get("scope", {})
                    if scope.get("type") == "user" and scope.get("value"):
                        email = scope["value"]
                        rule_id = regra.get("id")
                        # Guarda o rule_id se for um dos usuários que queremos modificar
                        if email in user_emails and rule_id:
                             rule_map[(calendar_id, email)] = rule_id
                             logger.debug(f"Phase 1 Found ruleId for {email} in {calendar_id}: {rule_id}")

        batch_list = servico.new_batch_http_request(callback=process_list_callback)
        calendars_added_to_list_batch = 0
        for cal_id in calendar_ids:
            batch_list.add(servico.acl().list(calendarId=cal_id), request_id=cal_id)
            calendars_added_to_list_batch += 1

        if len(batch_list._requests) > 0:
            try:
                # Executa a listagem com retry para falhas do batch de listagem
                _execute_batch_with_retry(batch_list, list_errors, "list_rules")
            except Exception as list_batch_error:
                # Falha crítica na listagem, adiciona erro geral e retorna
                logger.critical(f"CRITICAL FAILURE during Phase 1 (listing rules): {list_batch_error}", exc_info=True)
                initial_errors["__phase1_critical__"] = f"Falha crítica ao listar regras: {list_batch_error}"
                # Retorna resultados/erros iniciais porque não podemos prosseguir
                return initial_results, initial_errors
            # Adiciona erros individuais da listagem aos erros finais
            if list_errors: initial_errors["__phase1_list_errors__"] = list_errors
        else:
            logger.warning("Phase 1: No calendars to list ACLs for.")
            # Pode retornar aqui ou continuar (depende se quer registrar falhas de não encontrado)


        logger.info(f"Phase 1 finished. Found {len(rule_map)} matching rule IDs.")

        # FASE 2: Preparar operações de Update ou Delete
        for cal_id in calendar_ids:
            for user_email in user_emails:
                op_key = (cal_id, user_email)
                request_id = f"{cal_id}{REQUEST_ID_SEPARATOR}{user_email}"

                if op_key in rule_map:
                    rule_id = rule_map[op_key]
                    api_call_partial = None
                    if action == 'editar':
                         if not isinstance(user_email, str) or '@' not in user_email: # Revalida
                              initial_results[cal_id][user_email] = "Formato de e-mail inválido (fase 2)."
                              initial_errors[request_id] = "Formato de e-mail inválido (fase 2)."
                              continue
                         nova_regra_body = {"role": role}
                         api_call_partial = partial(servico.acl().update, calendarId=cal_id, ruleId=rule_id, body=nova_regra_body)
                    elif action == 'remover':
                         api_call_partial = partial(servico.acl().delete, calendarId=cal_id, ruleId=rule_id)

                    if api_call_partial:
                        operations_to_execute.append({
                            "request_id": request_id,
                            "op_key": op_key,
                            "api_call_func": api_call_partial
                        })
                else:
                     # Rule ID não encontrado na Fase 1 - erro final registrado aqui
                     msg = f"Regra de acesso não encontrada para {action}."
                     logger.warning(f"Phase 2 prep: Rule ID not found for {user_email} in {cal_id}. Skipping.")
                     initial_results[cal_id][user_email] = msg
                     initial_errors[request_id] = msg

    prep_time = time.time() - start_prep_time
    logger.info(f"Preparation finished in {prep_time:.2f}s. {len(operations_to_execute)} operations queued for execution.")

    # Chama a função intermediária para executar as operações preparadas
    if operations_to_execute:
        batch_results, batch_run_errors = _execute_operations_with_item_retry(
            operations_to_execute,action, max_retries=MAX_ITEM_RETRIES
        )
        # Mescla os resultados e erros do batch run com os iniciais
        for op_key, result_message in batch_results.items():
            cal_id, user_email = op_key
            initial_results[cal_id][user_email] = result_message
        initial_errors.update(batch_run_errors) # Adiciona erros da execução

    else:
        logger.info("No operations to execute in batch.")


    # Retorna os resultados consolidados e os erros finais
    return initial_results, initial_errors



# --- Funções Auxiliares ---

def _is_retryable_error(exception):
    # ...(sem mudanças)...
    if not isinstance(exception, HttpError): return False
    return exception.resp.status in [403, 429, 500, 502, 503, 504]

@retry(
    stop=stop_after_attempt(4),
    wait=wait_random_exponential(multiplier=1, min=1, max=10),
    retry=(retry_if_exception_type(HttpError) & retry_if_exception(_is_retryable_error)),
    before_sleep=lambda rs: logger.warning(f"Batch execution hit retryable error (Phase '{rs.args[2]}'). Retrying in {rs.next_action.sleep:.2f}s (Attempt {rs.attempt_number})... Last exception: {rs.outcome.exception()}")
)

def _execute_batch_with_retry(batch_request, errors_list, phase_name):
    """Executa um batch request, tratando erros GERAIS da execução com retry."""
    # A execução real acontece aqui. Se levantar HttpError retentável, o @retry vai agir.
    try:
        start_exec_time = time.time()
        logger.debug(f"Attempting batch execution for phase '{phase_name}'...")
        batch_request.execute() # Executa o batch
        end_exec_time = time.time()
        logger.info(f"Batch execution for phase '{phase_name}' SUCCESSFUL in {end_exec_time - start_exec_time:.2f} seconds.")
    except HttpError as e:
        # Se o erro NÃO for retentável pelo @retry, ou se as retentativas falharem, cairá aqui.
        logger.error(f"Non-retryable HTTP error or final retry failed during batch execution (Phase '{phase_name}'): {e}", exc_info=True)
        errors_list.append({f"__batch_error_{phase_name}__": f"HTTP Error: {str(e)}"})
        # Re-levanta a exceção para que, se desejado, o chamador possa saber que falhou
        raise e
    except Exception as e:
        # Captura outros erros inesperados
        logger.error(f"Fatal unexpected error during batch execution (Phase '{phase_name}'): {e}", exc_info=True)
        errors_list.append({f"__batch_error_{phase_name}__": f"Unexpected Error: {str(e)}"})
        raise e # Re-levanta
    

def _execute_operations_with_item_retry(operations: list[dict], action_name:str, max_retries: int, servico=servico) -> tuple[dict, dict]:
    """
    Executa uma lista de operações da API em lote, com retentativas para itens
    individuais que falham com erros retentáveis (ex: rate limit).

    Parâmetros:
        operations: Lista de dicionários, cada um descrevendo uma operação:
                    {'request_id': str, 'op_key': tuple, 'api_call_func': partial}
        servico: Instância do serviço Google Calendar.
        action_name: Nome da ação principal (para logs).
        max_retries: Número máximo de retentativas para itens individuais.

    Retorna:
        Uma tupla contendo:
        - dict: Dicionário de resultados bem-sucedidos {op_key: message}.
        - dict: Dicionário de erros finais {request_id_string: error_message}.
    """
    pending_ops = list(operations) # Cria cópia da lista de operações pendentes
    successful_results = {} # {op_key: message}
    final_item_errors = {} # {request_id: error_message}
    current_attempt = 0

    while current_attempt <= max_retries and pending_ops:
        current_attempt += 1
        logger.info(f"Item Retry Attempt {current_attempt}/{max_retries+1} for {len(pending_ops)} pending operations ({action_name}).")

        current_batch_errors = [] # Erros do batch.execute() desta tentativa
        attempt_results = {} # Resultados individuais desta tentativa {op_key: {'status':..., 'message':..., 'exception':...}}

        # Callback específico para esta tentativa
        def attempt_callback(request_id, response, exception):
             try:
                 # Encontra a operação original pelo request_id para obter o op_key
                 op_data = next((op for op in pending_ops if op["request_id"] == request_id), None)
                 if not op_data:
                      logger.error(f"Internal Error: Could not find operation data for request_id '{request_id}' in callback.")
                      # Registra erro, mas não temos op_key para attempt_results
                      final_item_errors[request_id] = "Internal error finding operation data in callback."
                      return
                 op_key = op_data["op_key"]
             except Exception as e:
                 logger.error(f"Internal Error: Processing request_id '{request_id}' in callback: {e}")
                 final_item_errors[request_id] = f"Internal error processing callback: {e}"
                 return

             if exception:
                 error_message = str(exception)
                 status_code = getattr(exception, 'resp', {}).get('status', 'N/A')
                 logger.warning(f"Attempt {current_attempt}: Item Error {op_key} (Status: {status_code}): {error_message}")
                 if _is_retryable_error(exception) and current_attempt <= max_retries:
                     attempt_results[op_key] = {'status': 'failed_retryable', 'message': error_message, 'exception': exception}
                 else:
                     attempt_results[op_key] = {'status': 'failed_final', 'message': error_message, 'exception': exception}
             else:
                 logger.debug(f"Attempt {current_attempt}: Item Success {op_key}")
                 # Define a mensagem de sucesso baseada na ação (poderia ser mais genérico)
                 if action_name == 'adicionar': msg = f"Acesso adicionado: {response.get('role', 'N/A')}"
                 elif action_name == 'editar': msg = f"Acesso atualizado para: {response.get('role', 'N/A')}"
                 elif action_name == 'remover': msg = "Acesso removido com sucesso."
                 else: msg = "Operação concluída."
                 attempt_results[op_key] = {'status': 'success', 'message': msg, 'exception': None}

        # Cria e popula o batch para esta tentativa
        batch = servico.new_batch_http_request(callback=attempt_callback)
        items_in_this_batch = 0
        for op_data in pending_ops:
            try:
                # Adiciona a chamada da API pré-configurada (partial)
                batch.add(op_data["api_call_func"](), request_id=op_data["request_id"])
                items_in_this_batch += 1
            except Exception as add_err:
                # Erro ao tentar adicionar ao batch (ex: erro na função partial?)
                logger.error(f"Error adding operation {op_data['request_id']} to batch: {add_err}")
                final_item_errors[op_data["request_id"]] = f"Error adding to batch: {add_err}"
                # Marca como falha final para não tentar de novo
                attempt_results[op_data["op_key"]] = {'status':'failed_final', 'message':f"Error adding to batch: {add_err}", 'exception': add_err}


        if items_in_this_batch == 0:
            logger.info(f"Attempt {current_attempt}: No pending operations to execute in batch.")
            break # Sai do loop while

        # Executa o batch desta tentativa
        try:
            _execute_batch_with_retry(batch, current_batch_errors, f"{action_name}_item_attempt_{current_attempt}")
        except Exception as batch_exec_error:
             logger.error(f"Attempt {current_attempt}: CRITICAL - Batch execution failed definitively for phase {action_name}. Aborting further item retries.")
             # Marca todos os itens *deste batch* como falha final
             for op_data in pending_ops:
                 if op_data["op_key"] not in attempt_results:
                    error_msg = f"Batch execution failed: {batch_exec_error}"
                    attempt_results[op_data["op_key"]] = {'status': 'failed_final', 'message': error_msg, 'exception': batch_exec_error}
                    final_item_errors[op_data["request_id"]] = error_msg
             pending_ops = [] # Limpa para sair do loop
             break # Sai do loop while

        # Processa resultados e prepara próxima lista de pendentes
        next_pending_ops = []
        processed_keys_this_attempt = set(attempt_results.keys())

        for op_data in pending_ops:
            op_key = op_data["op_key"]
            if op_key in attempt_results:
                result_info = attempt_results[op_key]
                if result_info['status'] == 'success':
                    successful_results[op_key] = result_info['message']
                elif result_info['status'] == 'failed_final':
                    final_item_errors[op_data["request_id"]] = result_info['message']
                elif result_info['status'] == 'failed_retryable':
                    next_pending_ops.append(op_data) # Adiciona para a próxima tentativa
            else:
                # Não deveria acontecer se o batch executou, mas por segurança
                logger.error(f"Attempt {current_attempt}: Operation {op_key} has no result after batch exec. Marking final failure.")
                final_item_errors[op_data["request_id"]] = "Internal processing error - missing result."

        # Verifica se algum item no batch não foi processado pelo callback (erro interno no batch?)
        ops_in_batch_not_processed = [op for op in pending_ops if op['op_key'] not in processed_keys_this_attempt]
        if ops_in_batch_not_processed:
            logger.error(f"Attempt {current_attempt}: {len(ops_in_batch_not_processed)} operations were in batch but not processed by callback!")
            for op_data in ops_in_batch_not_processed:
                final_item_errors[op_data["request_id"]] = "Failed: No response in batch result."
                # Remove da lista de pendentes para não tentar de novo
                if op_data in next_pending_ops: next_pending_ops.remove(op_data)


        pending_ops = next_pending_ops # Atualiza a lista para o próximo loop

        # Backoff antes da próxima tentativa
        if pending_ops and current_attempt <= max_retries:
            wait_time = min(1 * (2 ** (current_attempt - 1)), 10) + random.uniform(0, 0.5)
            logger.info(f"Attempt {current_attempt} finished. {len(pending_ops)} items failed retryable. Waiting {wait_time:.2f}s...")
            time.sleep(wait_time)

    # Tratamento final para itens que excederam retentativas
    if pending_ops:
        logger.warning(f"Exceeded max item retries ({max_retries}). {len(pending_ops)} operations failed definitively.")
        for op_data in pending_ops:
            request_id = op_data["request_id"]
            op_key = op_data["op_key"]
            last_error_msg = "Unknown retryable error"
            # Tenta pegar a última mensagem de erro registrada
            if op_key in attempt_results and attempt_results[op_key]['status'] == 'failed_retryable':
                last_error_msg = attempt_results[op_key]['message']
            final_error_msg = f"Failed after {max_retries + 1} attempts: {last_error_msg}"
            final_item_errors[request_id] = final_error_msg

    logger.info(f"Item retry loop finished. Success: {len(successful_results)}, Final Failures: {len(final_item_errors)}.")
    return successful_results, final_item_errors