from flask import Flask, render_template, request, jsonify
import concurrent.futures
import logging
from funcoes_google import (
    create_calendars_batch,
    calendarios,
    renomear_calendario,
    listar_usuarios_calendario,
    modify_acl_users_batch,
    get_acl_users_batch
)

app = Flask(__name__)

# ────────────────────────────────────────────────────────────────────────────────
# ROUTES
# ────────────────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    """Renderiza a página principal com todos os dados para o frontend."""
    try:
        all_cals = calendarios()
        if all_cals is None:
            all_cals = []

        unique_users = {}
        
        # Agrupa usuários por calendário e coleta usuários únicos
        for cal in all_cals:
            # Anexa a lista de usuários a cada objeto de calendário
            users_in_cal = listar_usuarios_calendario(cal.get('id'))
            cal['users'] = users_in_cal
            
            # Adiciona os usuários a um dicionário para garantir unicidade
            for user in users_in_cal:
                email = user.get('email')
                if email not in unique_users:
                    unique_users[email] = {'value': email, 'label': email}

        # Converte o dicionário de usuários únicos em uma lista para o Choices.js
        calendar_choices_list = [
            {'value': cal.get('id'), 'label': cal.get('summary', 'Nome Indisponível')}
            for cal in all_cals if cal.get('id')
        ]
        
        unique_users_list = list(unique_users.values())

    except Exception as e:
        app.logger.error(f"Erro ao buscar dados para a página inicial: {e}", exc_info=True)
        all_cals = []
        calendar_choices_list = []
        unique_users_list = []
        # Adicionar um flash message de erro aqui seria uma boa prática

    return render_template(
        "index.html",
        calendarios=all_cals,
        calendar_choices_list=calendar_choices_list,
        unique_users_list=unique_users_list # Nova variável para os filtros
    )


@app.post("/api/calendars/bulk_create")
def handle_bulk_create_calendars():
    """Endpoint para criar múltiplos calendários a partir de uma lista de nomes."""

    data = request.get_json()
    if not data or 'names' not in data:
        return jsonify(error="Missing 'names' field (must be a list of strings)"), 400

    names_list = data.get('names', [])
    if not isinstance(names_list, list):
        return jsonify(error="'names' field must be a list"), 400
    # Não precisa verificar se a lista está vazia aqui, a função utilitária faz isso

    app.logger.info(f"Endpoint /api/calendars/bulk_create called for {len(names_list)} names.")

    try:
        # Chama a função utilitária de criação em lote
        final_results_map, final_consolidated_errors = create_calendars_batch(names_list)

        # Prepara a resposta para o frontend
        response_data = {
            # Retorna o mapa nome_original -> {'status': 'success'/'failed', 'message': '...'}
            "results_by_name": final_results_map,
            # Retorna erros gerais ou de itens que falharam de forma irrecuperável
            "errors": final_consolidated_errors
        }
        success_count = sum(1 for res in final_results_map.values() if res.get('status') == 'success')
        failure_count = len(final_results_map) - success_count
        app.logger.info(f"Bulk creation processed. Success: {success_count}, Failures: {failure_count}. General/Item Errors: {len(final_consolidated_errors)}")

        status_code = 200
        if final_consolidated_errors or failure_count > 0:
             status_code = 207 # Multi-Status

        return jsonify(response_data), status_code

    except Exception as e:
        app.logger.error(f"Unexpected error during bulk calendar creation processing: {e}", exc_info=True)
        return jsonify(error="Internal server error during bulk creation"), 500


@app.post("/calendar/<cal_id>/rename")
def calendar_rename(cal_id):
    new_name = request.form.get("name", "").strip()
    if not new_name:
        return jsonify(error="O nome não pode ficar vazio."), 400
    try:
        renomear_calendario(cal_id, new_name)
        return jsonify(success=True)
    except Exception as e:
        return jsonify(error=str(e)), 500


@app.get("/calendar/<cal_id>/users")
def calendar_users(cal_id):
    """Retorna lista de usuários + role (JSON) para preencher modal."""
    try:
        users = listar_usuarios_calendario(cal_id)
        return jsonify(users=users)
    except Exception as e:
        return jsonify(error=str(e)), 500


@app.route('/acl/bulk', methods=['POST']) # Use route decorator do Flask
def handle_acl_bulk():
    """
    Endpoint para modificar ACLs de múltiplos usuários/calendários em lote.
    """

    data = request.get_json(force=True) # force=True pode ser útil se o content-type não for setado corretamente
    if not data:
        return jsonify(error="Request body must be JSON."), 400

    calendars = data.get("calendars")
    users = data.get("users")
    action = data.get("action")  # adicionar | remover | editar
    role = data.get("role")      # Necessário para adicionar/editar

    # Validações básicas de entrada
    if not isinstance(calendars, list) or not calendars:
        return jsonify(error="'calendars' (lista não vazia) é obrigatório."), 400
    if not isinstance(users, list) or not users:
        return jsonify(error="'users' (lista não vazia) é obrigatório."), 400
    if not action or action not in ['adicionar', 'remover', 'editar']:
        return jsonify(error="Ação inválida ('adicionar', 'remover', 'editar')."), 400
    if action in ['adicionar', 'editar'] and not role:
        return jsonify(error="'role' é obrigatório para 'adicionar' ou 'editar'."), 400

    app.logger.info(f"Endpoint /acl/bulk called. Action: {action}, Calendars: {len(calendars)}, Users: {len(users)}")

    # Chama a função do módulo utilitário
    try:
        # Chama a função principal que agora orquestra preparação E execução com retry
        final_results, final_errors = modify_acl_users_batch(calendars, users, action, role)

        response_data = {"results": final_results}
        if final_errors:
            # Log detalhado dos erros finais
            app.logger.warning(f"ACL modification completed with {len(final_errors)} final errors:")
            for err_key, err_msg in final_errors.items():
                 app.logger.warning(f"  - {err_key}: {err_msg}")
            # Inclui os erros consolidados na resposta
            response_data["final_errors"] = final_errors

        app.logger.info(f"Returning final results for {action}.")
        return jsonify(response_data), 200

    except Exception as e:
        app.logger.error(f"Unexpected error during ACL bulk processing: {e}", exc_info=True)
        return jsonify(error="Internal server error during ACL bulk processing"), 500
    
@app.route('/acl/users_for_calendars', methods=['POST'])
def handle_get_users_for_calendars():
    """
    Endpoint para receber uma lista de IDs de calendário e retornar usuários únicos.
    Utiliza a função de batch do módulo google_calendar_utils.
    """

    # Obtém os dados da requisição
    data = request.get_json()
    if not data or 'calendars' not in data:
        app.logger.warning("Request received without 'calendars' field.")
        return jsonify(error="Missing 'calendars' field in request body"), 400

    calendar_ids = data.get('calendars', [])
    if not isinstance(calendar_ids, list):
        app.logger.warning("Field 'calendars' is not a list.")
        return jsonify(error="'calendars' field must be a list"), 400

    app.logger.info(f"Endpoint called for {len(calendar_ids)} calendars.")

    # Chama a função do módulo utilitário para processar em batch
    try:
        unique_users_list, errors = get_acl_users_batch(calendar_ids)

        # Loga se houveram erros durante o processamento do batch
        if errors:
            app.logger.warning(f"Batch processing completed with errors for {len(errors)} items. Check utils logs for details.")
            # Opcional: Incluir os erros na resposta
            # return jsonify(users=unique_users_list, processing_errors=errors)

        app.logger.info(f"Returning {len(unique_users_list)} unique users.")
        return jsonify(users=unique_users_list)

    except Exception as e:
        # Captura qualquer erro inesperado ao chamar a função utilitária
        app.logger.error(f"Unexpected error calling batch utility function: {e}", exc_info=True)
        return jsonify(error="Internal server error during batch processing"), 500


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000)