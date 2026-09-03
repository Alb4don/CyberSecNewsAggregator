### `Start`


<img width="1258" height="642" alt="cybernewsfront" src="https://github.com/user-attachments/assets/8a308215-63a3-4d41-8360-be5915cb9645" />

- Python 3.10+ with Pydantic v2, on Windows or Linux.

      pip install fastapi uvicorn httpx feedparser


      python cybersecnews.py

- Open http://127.0.0.1:8000.

- Docker, with a hardened container (read-only root filesystem, all capabilities dropped, unprivileged user, port pinned to loopback):

      docker compose up -d --build

- For Tor or any SOCKS5 proxy on the fetch path:

      pip install socksio
      FEED_PROXY=socks5://127.0.0.1:9050 python app.py

- On Docker Desktop, FEED_PROXY=socks5://host.docker.internal:9050 reaches a Tor daemon on the host from inside the container.

### `Keyboard`

      | Key | Action |
      |---|---|
      | `r` | Force refresh |
      | `/` | Focus search |
      | `j` / `k` | Next / previous article |
      | `o` | Open selected article in a new tab, mark read |
      | `b` | Star selected article |
      | `m` | Toggle read on selected article |
      | `Esc` | Close modal or leave an input |


### `API`

      | Route | Purpose |
      |---|---|
      | `GET /` | UI |
      | `GET /api/feeds` | Current headlines, optional `filter` and `refresh` |
      | `GET /api/history` | Stored articles, paginated, filterable |
      | `GET / POST /api/sources` | List / add feeds |
      | `PATCH / DELETE /api/sources/{id}` | Enable-disable / remove custom feeds |
      | `GET /api/preview?url=` | Clean-text article extraction |
      | `GET /api/opml/export`, `POST /api/opml/import` | OPML |
      | `GET /api/export` | History as JSON download |
      | `GET /api/health` | Liveness |


