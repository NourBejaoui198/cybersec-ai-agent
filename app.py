import gradio as gr
from gradio import ChatMessage
from agent import run_agent

EXEMPLES = [
    ["Analyse ce mot de passe : P@ssw0rd123!"],
    ["Scanne le site example.com"],
    ["Explique l'attaque SQL Injection"],
    ["Mon mot de passe est admin123, est-il sécurisé ?"],
    ["Qu'est-ce que le phishing ?"],
]


def chat(message: str, historique: list):
    if not message.strip():
        return historique, ""

    # Convertir l'historique ChatMessage → format OpenAI
    hist_openai = []
    for msg in historique:
        if isinstance(msg, ChatMessage):
            hist_openai.append({"role": msg.role, "content": msg.content})

    try:
        reponse = run_agent(message, hist_openai)
    except Exception as e:
        reponse = f"❌ Erreur : {e}"

    historique.append(ChatMessage(role="user",      content=message))
    historique.append(ChatMessage(role="assistant", content=reponse))
    return historique, ""


with gr.Blocks(title="CyberSec AI Agent") as demo:

    gr.Markdown("# 🔐 CyberSec AI Agent\nAgent IA spécialisé en cybersécurité")

    chatbot = gr.Chatbot(label="Chat", height=450)

    with gr.Row():
        msg = gr.Textbox(placeholder="Pose ta question...", show_label=False, scale=5)
        envoyer = gr.Button("Envoyer", variant="primary", scale=1)

    effacer = gr.Button("🗑️ Effacer la conversation")

    gr.Examples(examples=EXEMPLES, inputs=msg, label="Exemples")

    envoyer.click(fn=chat, inputs=[msg, chatbot], outputs=[chatbot, msg])
    msg.submit(fn=chat,    inputs=[msg, chatbot], outputs=[chatbot, msg])
    effacer.click(fn=lambda: ([], ""), outputs=[chatbot, msg])


if __name__ == "__main__":
    demo.launch(server_port=7860)
