(() => {
  "use strict";
  const $ = (id) => document.getElementById(id);
  const feedLimit = 20;
  const labels = {apt:"APT", detection:"Detecção", dfir:"DFIR", exploit:"Exploits", government:"Governo", malware:"Malware", news:"Notícias", osint:"OSINT", podcasts:"Podcasts", threat_hunting:"Threat hunting", threat_intelligence:"Threat intelligence", vendors:"Fornecedores", vulnerability:"Vulnerabilidades"};
  const number = new Intl.NumberFormat("pt-BR");
  const scores = new Intl.NumberFormat("pt-BR", {maximumFractionDigits:3});
  const dates = new Intl.DateTimeFormat("pt-BR", {day:"2-digit", month:"short", year:"numeric"});
  const timestamps = new Intl.DateTimeFormat("pt-BR", {dateStyle:"short", timeStyle:"short"});
  let state = readURL(), articleController, detailController, feedController, topicController, sourceController, backupController;
  let backupTimer, backupRunning=false, backupRequest=false;
  let configuredFeeds=[], editingFeed=null, sourceRequest=false;
  let collectionTimer, collectionWasRunning=false, collectionRequest=false;
  let facets = {categories:[], sources:[], tags:[], total:0};
  const categoryName = (value) => labels[value] || value;
  const formatDate = (value, full=false) => {
    if (!value || !Number.isFinite(new Date(value).getTime())) return "Sem data registrada";
    return (full ? timestamps : dates).format(new Date(value));
  };
  function readURL() {
    const params = new URLSearchParams(location.search);
    const q = (params.get("q") || "").slice(0,500);
    const offset = Math.max(0, Math.floor(Number(params.get("offset")) || 0));
    const resultLimit=[10,20,50,100].includes(Number(params.get("limit"))) ? Number(params.get("limit")) : 20;
    const threshold=Number(params.get("fuzzy_threshold") ?? 80);
    return {limit:resultLimit,order:params.get("order")==="oldest" ? "oldest" : "newest",period:["today","week"].includes(params.get("period")) ? params.get("period") : "all",match:params.get("match")==="exact" ? "exact" : "fuzzy",fuzzy_threshold:Number.isInteger(threshold) && threshold>=0 && threshold<=100 ? threshold : 80,q, category:(params.get("category") || "").slice(0,200), source:(params.get("source") || "").slice(0,200), tag:(params.get("tag") || "").slice(0,200), offset:Math.min(q ? 10000 : 1000000, offset), view:["feeds","topics","sources","backups"].includes(params.get("view")) ? params.get("view") : "articles", topicLimit:[10,20,50,100].includes(Number(params.get("topicLimit"))) ? Number(params.get("topicLimit")) : 20, feedStatus:["success","error","collecting"].includes(params.get("status")) ? params.get("status") : "", feedOffset:Math.min(1000000, Math.max(0, Math.floor(Number(params.get("feedOffset")) || 0))), article:params.get("article") || ""};
  }
  function writeURL(replace=false) {
    const params = new URLSearchParams();
    for (const key of ["q","category","source","tag","offset","article"]) if (state[key]) params.set(key,state[key]);
    for(const [key,value] of Object.entries({limit:20,order:"newest",period:"all",match:"fuzzy",fuzzy_threshold:80})) if(state[key]!==value) params.set(key,state[key]);
    if (state.view === "feeds") {params.set("view","feeds"); if(state.feedStatus) params.set("status",state.feedStatus); if(state.feedOffset) params.set("feedOffset",state.feedOffset);}
    if(["topics","sources","backups"].includes(state.view)) params.set("view",state.view);
    if(state.topicLimit!==20) params.set("topicLimit",state.topicLimit);
    const url = location.pathname + (params.size ? "?" + params.toString() : "");
    history[replace ? "replaceState" : "pushState"](null,"",url);
  }
  function element(tag, className, text) {
    const node = document.createElement(tag);
    if(className) node.className = className;
    if(text !== undefined) node.textContent = text;
    return node;
  }
  function button(text, className, action) {
    const node = element("button",className,text); node.type = "button"; node.addEventListener("click",action); return node;
  }
  async function request(path, signal) {
    const response = await fetch(path,{signal, headers:{Accept:"application/json"}});
    if(!response.ok) throw new Error(`HTTP ${response.status}`);
    return response.json();
  }
  function message(id, title, description, retry) {
    const node=$(id); node.replaceChildren(element("h3","",title), element("p","",description));
    if(retry) node.append(button("Tentar novamente","secondary-button",retry));
    node.hidden=false;
  }
  function categoryNavigation() {
    $("categories").replaceChildren(...facets.categories.map(({value,count}) => {
      const node=button(categoryName(value),"category-button" + (value===state.category ? " active" : ""),() => updateArticles({category:value}));
      node.setAttribute("aria-pressed",String(value===state.category));
      node.append(element("span","category-count",number.format(count)));
      return node;
    }));
  }
  function controls() {
    $("search").value=state.q; $("source").value=state.source; $("tag").value=state.tag;
    $("result-limit").value=state.limit;$("result-order").value=state.order;$("result-period").value=state.period;
    $("search-match").value=state.match;$("search-match").disabled=!state.q;
    $("fuzzy-threshold").value=state.fuzzy_threshold;$("fuzzy-threshold").disabled=!state.q || state.match==="exact";
    $("feed-filter").value=state.feedStatus;
    $("topics-limit").value=state.topicLimit;
    for(const view of ["articles","topics","feeds","sources","backups"]) {
      $(view+"-section").hidden=state.view!==view;
      $("nav-"+view).classList.toggle("active",state.view===view);
      $("nav-"+view).setAttribute("aria-current",state.view===view ? "page" : "false");
    }
    const views={backups:["Backups","Seu histórico protegido","Gere e guarde cópias do seu arquivo de artigos."],sources:["Gerenciar feeds","Fontes do seu radar","Configure o que será acompanhado nas próximas coletas."],articles:["Artigos","Seu radar de ameaças","Notícias, pesquisas e indicadores em um só lugar."], feeds:["Coleta de feeds","Fontes sob observação","Acompanhe tentativas, sucessos e erros de cada fonte."], topics:["Tópicos","Assuntos em destaque","Explore os termos mais relevantes do seu arquivo."]};
    const [section,title,description]=views[state.view];
    $("breadcrumb-section").textContent=section;
    $("page-title").replaceChildren(document.createTextNode(title),element("span","","."));
    $("page-description").textContent=description;
    $("results-title").textContent=state.q ? `Resultados para “${state.q}”` : (state.category ? categoryName(state.category) : "Últimos artigos");
    $("active-category").hidden=!state.category;
    $("active-category").textContent=categoryName(state.category);
    categoryNavigation();
  }
  const mobileNavigation = window.matchMedia("(max-width:800px)");
  function syncMenuAccessibility() {$("sidebar").inert=mobileNavigation.matches && !$("sidebar").classList.contains("open");}
  function closeMenu() {$("sidebar").classList.remove("open"); $("menu-toggle").setAttribute("aria-expanded","false");syncMenuAccessibility();}
  function updateArticles(changes) {
    state={...state,...changes,offset:0,view:"articles",article:""}; closeMenu(); closeDetail(false); writeURL(); controls(); loadView();
  }
  function navigate(view, feedStatus="") {
    state.view=view; state.feedStatus=feedStatus; state.feedOffset=0; state.article="";
    closeMenu(); closeDetail(false); writeURL(); controls();
    loadView();
  }
  async function loadFacets() {
    facets=await request("/filters");
    $("stat-articles").textContent=number.format(facets.total);
    const options=[element("option","","Todas as fontes"),...facets.sources.map(({value,count}) => {const option=element("option","",`${value} (${number.format(count)})`); option.value=value; return option;})];
    options[0].value="";
    if(state.source && !facets.sources.some(s=>s.value===state.source)) {const option=element("option","",state.source); option.value=state.source; options.push(option);}
    $("source").replaceChildren(...options);
    $("tag-options").replaceChildren(...facets.tags.map(({value}) => {const option=element("option"); option.value=value; return option;}));
    controls();
  }
  function renderStats(data) {
    $("stat-feeds").textContent=number.format(data.summary.success);
    $("stat-feeds-note").textContent=data.summary.total ? `${data.summary.total} feeds observados · ${data.summary.collecting} em coleta` : "Nenhuma coleta registrada";
    $("stat-errors").textContent=number.format(data.summary.error);
    $("nav-errors").hidden=!data.summary.error; $("nav-errors").textContent=data.summary.error;
  }
  async function loadSummary() {
    const data=await request("/feeds?limit=100"); renderStats(data);
    // Follow pages to include the last success of every observed feed.
    const rows=[...data.items]; let offset=100, page=data;
    while(page.has_more) {page=await request(`/feeds?limit=100&offset=${offset}`);rows.push(...page.items);offset+=100;}
    const successes=rows.map(row=>row.last_success).filter(Boolean).sort();
    if(successes.length) {const latest=successes.at(-1);$("stat-success").textContent=new Intl.DateTimeFormat("pt-BR",{hour:"2-digit",minute:"2-digit"}).format(new Date(latest));$("stat-success-note").textContent=formatDate(latest);}
    else {$("stat-success").textContent="—";$("stat-success-note").textContent="Nenhuma coleta registrada";}
  }
  function renderArticle(article) {
    const card=element("article","article-card");
    const meta=element("div","article-meta");
    meta.append(element("span","article-source",article.source),element("span","pill category-pill",categoryName(article.category || "Sem categoria")),element("time","article-date",formatDate(article.published)));
    const published=meta.querySelector("time"); if(article.published) published.dateTime=article.published;
    const open=()=>openDetail(article.id);
    const title=button(article.title,"article-title",open);
    const summary=element("p","article-summary",(article.summary || "Resumo não disponível neste feed.").slice(0,600).replace(/\s+/g," "));
    const bottom=element("div","article-bottom"), tags=element("div","article-tags");
    article.tags.slice(0,3).forEach(tag=>tags.append(button(tag,"pill",()=>updateArticles({tag}))));
    if(article.iocs.length) tags.append(element("span","pill entity-pill",`${article.iocs.length} IOC${article.iocs.length===1 ? "" : "s"}`));
    bottom.append(tags,button("Ver detalhes ↗","detail-button",open));
    card.append(meta,title,summary,bottom); return card;
  }
  async function loadArticles() {
    articleController?.abort(); const controller=articleController=new AbortController();
    $("article-list").setAttribute("aria-busy","true");$("article-list").classList.add("loading");
    $("articles-message").hidden=true; $("next").disabled=true;$("previous").disabled=true;$("results-note").textContent="Carregando artigos…";
    const params=new URLSearchParams({limit:state.limit,offset:state.offset,order:state.order,period:state.period});
    for(const key of ["q","category","source","tag"]) if(state[key]) params.set(key,state[key]);
    if(state.q) {params.set("match",state.match);params.set("fuzzy_threshold",state.fuzzy_threshold);}
    try {
      const data=await request((state.q ? "/search?" : "/articles?")+params,controller.signal);
      if(controller!==articleController) return;
      $("article-list").replaceChildren(...data.items.map(renderArticle));
      $("results-note").textContent=`${data.items.length} ${data.items.length===1 ? "artigo" : "artigos"} nesta página`;
      $("page-number").textContent=`Página ${Math.floor(state.offset/state.limit)+1}`;
      $("previous").disabled=state.offset===0;
      $("next").disabled=!data.has_more || Boolean(state.q && state.offset+state.limit>10000);
      if(!data.items.length) message("articles-message",(facets.total || state.q || state.category || state.source || state.tag || state.offset) ? "Nenhum artigo encontrado" : "Seu arquivo está pronto para começar",(facets.total || state.q || state.category || state.source || state.tag || state.offset) ? "Tente outra busca ou ajuste os filtros." : "Os artigos aparecerão aqui após a primeira coleta.");
    } catch(error) {
      if(error.name==="AbortError") return;
      $("article-list").replaceChildren(); $("results-note").textContent="Consulta indisponível";
      message("articles-message","Não foi possível carregar os artigos","Verifique a conexão e tente novamente.",loadArticles);
    } finally {
      if(controller===articleController) {$("article-list").setAttribute("aria-busy","false");$("article-list").classList.remove("loading");}
    }
  }
  function renderFeed(feed) {
    const card=element("article","feed-card"),top=element("div","feed-top"),name=element("div");
    name.append(element("h3","",feed.name),element("div","feed-url",feed.url));
    top.append(name,element("span",`pill badge-${feed.status}`,{success:"Com sucesso",error:"Com erro",collecting:"Coletando"}[feed.status]));
    const metrics=element("div","feed-metrics");
    for(const [label,value] of [["Última tentativa",formatDate(feed.last_attempt,true)],["Último sucesso",feed.last_success ? formatDate(feed.last_success,true) : "Sem sucesso registrado"],["Artigos no último sucesso",feed.last_success_article_count===null ? "—" : number.format(feed.last_success_article_count)]]) {const item=element("div");item.append(element("small","",label),element("span","",value));metrics.append(item);}
    card.append(top,metrics);
    if(feed.last_error) card.append(element("p","feed-error",feed.last_error));
    feed.warnings.forEach(warning=>card.append(element("p","feed-error feed-warning",warning)));
    if(feed.status==="collecting") card.append(element("p","stale-note","Coleta em andamento. Se este estado persistir, confira a data da última tentativa."));
    return card;
  }
  async function loadFeeds() {
    feedController?.abort(); const controller=feedController=new AbortController();
    $("feed-list").classList.add("loading");$("feeds-message").hidden=true;$("feeds-next").disabled=true;$("feeds-previous").disabled=true;
    const params=new URLSearchParams({limit:feedLimit,offset:state.feedOffset});if(state.feedStatus) params.set("status",state.feedStatus);
    try {
      const data=await request("/feeds?"+params,controller.signal); if(controller!==feedController) return;
      renderStats(data); $("feed-list").replaceChildren(...data.items.map(renderFeed));
      $("feeds-page").textContent=`Página ${Math.floor(state.feedOffset/feedLimit)+1}`;
      $("feeds-next").disabled=!data.has_more;$("feeds-previous").disabled=!state.feedOffset;
      if(!data.items.length) message("feeds-message","Nenhum feed neste estado",data.summary.total ? "Selecione outro estado para ver as fontes." : "Os estados aparecerão após a primeira coleta.");
    } catch(error) {if(error.name!=="AbortError") {$("feed-list").replaceChildren();message("feeds-message","Não foi possível carregar os feeds","Tente novamente para consultar o estado das fontes.",loadFeeds);}}
    finally {if(controller===feedController) $("feed-list").classList.remove("loading");}
  }
  function loadView() {
    if(state.view!=="topics") topicController?.abort();
    if(state.view!=="sources") sourceController?.abort();
    if(state.view!=="backups") {backupController?.abort();clearTimeout(backupTimer);}
    if(state.view==="backups") return Promise.allSettled([loadBackups(),loadBackupStatus(false)]);
    if(state.view==="sources") return loadSources();
    return state.view==="topics" ? loadTopics() : (state.view==="feeds" ? loadFeeds() : loadArticles());
  }
  async function loadTopics() {
    topicController?.abort();const controller=topicController=new AbortController();
    $("topic-list").setAttribute("aria-busy","true");$("topic-list").classList.add("loading");
    $("topics-message").hidden=true;$("topics-summary").textContent="Calculando tópicos do arquivo…";
    try {
      const data=await request("/topics?"+new URLSearchParams({limit:state.topicLimit}),controller.signal);
      if(controller!==topicController) return;
      const maximum=Math.max(1,...data.items.map(topic=>topic.score));
      $("topic-list").replaceChildren(...data.items.map((topic,index)=>{
        const card=button("","topic-card",()=>updateArticles({q:topic.topic,category:"",source:"",tag:"",period:"all"}));
        const top=element("span","topic-top");top.append(element("span","topic-rank",String(index+1).padStart(2,"0")),element("span","topic-term",topic.topic));
        const relevance=element("meter","topic-relevance");relevance.min=0;relevance.max=maximum;relevance.value=topic.score;relevance.setAttribute("aria-label",`Relevância de ${topic.topic}`);
        const bottom=element("span","topic-bottom");bottom.append(element("span","",`Relevância ${scores.format(topic.score)}`),element("span","topic-action","Buscar artigos ↗"));
        card.append(top,relevance,bottom);return card;
      }));
      $("topics-summary").textContent=`${number.format(data.items.length)} ${data.items.length===1 ? "tópico disponível" : "tópicos disponíveis"} · arquivo completo`;
      if(!data.items.length) message("topics-message","Nenhum tópico disponível","Colete artigos com títulos e resumos para explorar os assuntos do arquivo.");
    } catch(error) {
      if(error.name==="AbortError") return;
      $("topic-list").replaceChildren();$("topics-summary").textContent="Tópicos indisponíveis";
      message("topics-message","Não foi possível carregar os tópicos","Verifique a conexão e tente novamente.",loadTopics);
    } finally {
      if(controller===topicController) {$("topic-list").setAttribute("aria-busy","false");$("topic-list").classList.remove("loading");}
    }
  }
  function renderSources() {
    const filter=$("sources-filter").value;
    const rows=configuredFeeds.filter(feed=>!filter || feed.enabled===(filter==="enabled"));
    $("source-list").replaceChildren(...rows.map(feed=>{
      const card=element("article","feed-card"),top=element("div","feed-top"),name=element("div");
      name.append(element("h3","",feed.name),element("div","feed-url",feed.url));
      top.append(name,element("span","pill "+(feed.enabled ? "badge-success" : ""),feed.enabled ? "Ativado" : "Desativado"));
      const actions=element("div","source-actions");actions.append(element("span","pill",categoryName(feed.category)),button("Editar","secondary-button feed-manage-action",()=>openFeed(feed)),button(feed.enabled ? "Desativar" : "Ativar","secondary-button feed-manage-action",()=>saveFeed({...feed,enabled:!feed.enabled},false)));
      card.append(top);if(feed.description) card.append(element("p","source-description",feed.description));card.append(actions);return card;
    }));
    $("sources-message").hidden=true;
    if(!rows.length) message("sources-message","Nenhum feed nesta seleção","Escolha outro estado ou adicione uma fonte.");
    syncFeedActions();
  }
  function syncFeedActions() {
    document.querySelectorAll(".feed-manage-action").forEach(node=>{node.disabled=collectionWasRunning || sourceRequest;});
  }
  async function loadSources() {
    sourceController?.abort();const controller=sourceController=new AbortController();
    $("source-list").setAttribute("aria-busy","true");$("sources-message").hidden=true;
    try {
      const data=await request("/feed-config",controller.signal);
      if(controller!==sourceController) return;
      configuredFeeds=data.items;
      $("sources-summary").textContent=`${number.format(data.total)} feeds · ${number.format(data.enabled)} ativados · ${number.format(data.total-data.enabled)} desativados`;
      $("feed-category-options").replaceChildren(...data.categories.map(value=>{const option=element("option");option.value=value;return option;}));
      renderSources();
    } catch(error) {
      if(error.name==="AbortError") return;
      $("source-list").replaceChildren();$("sources-summary").textContent="Configuração indisponível";
      message("sources-message","Não foi possível carregar a configuração","Verifique a conexão e tente novamente.",loadSources);
    } finally {if(controller===sourceController) $("source-list").setAttribute("aria-busy","false");}
  }
  function openFeed(feed=null) {
    editingFeed=feed;$("feed-form").reset();$("feed-form-error").hidden=true;
    $("feed-dialog-title").textContent=feed ? "Editar feed" : "Adicionar feed";
    $("feed-name").value=feed?.name || "";$("feed-url").value=feed?.url || "";
    $("feed-category").value=feed?.category || "news";$("feed-description").value=feed?.description || "";
    $("feed-enabled").checked=feed?.enabled ?? true;
    $("feed-dialog").showModal();$("feed-name").focus();
  }
  async function saveFeed(feed,fromForm=true) {
    if(sourceRequest) return;
    sourceRequest=true;syncFeedActions();
    const {id,...values}=feed;
    $("feed-form-error").hidden=true;$("sources-notice").hidden=true;
    try {
      const response=await fetch(id ? "/feed-config/"+encodeURIComponent(id) : "/feed-config",{method:id ? "PUT" : "POST",headers:{"Content-Type":"application/json","X-Cyber-RSS-Request":"1"},body:JSON.stringify(values)});
      if(!response.ok) {
        const data=await response.json();
        throw new Error(typeof data.detail==="string" ? data.detail : "Verifique o nome, a URL e a categoria do feed.");
      }
      if(fromForm) $("feed-dialog").close();
      $("sources-notice").textContent="Feed salvo. A configuração será usada na próxima coleta; o histórico foi preservado.";$("sources-notice").hidden=false;
      await loadSources();
    } catch(error) {
      const target=fromForm ? $("feed-form-error") : $("sources-notice");
      target.textContent=error.message==="Failed to fetch" ? "Não foi possível confirmar a alteração. Atualize a tela antes de tentar novamente." : error.message;target.hidden=false;
    } finally {sourceRequest=false;syncFeedActions();}
  }
  const fileSize=(bytes)=>bytes<1048576 ? `${number.format(bytes/1024)} KB` : `${number.format(bytes/1048576)} MB`;
  async function loadBackups() {
    backupController?.abort();const controller=backupController=new AbortController();
    $("backup-list").setAttribute("aria-busy","true");$("backups-message").hidden=true;
    try {
      const data=await request("/backups",controller.signal);if(controller!==backupController) return;
      $("backups-summary").textContent=`${number.format(data.items.length)} ${data.items.length===1 ? "cópia local disponível" : "cópias locais disponíveis"}`;
      $("backups-retention").textContent=`As últimas ${data.retention} cópias locais são mantidas, incluindo backups manuais e automáticos. Elas incluem artigos, estado da coleta e feeds gerenciados pela web.`;
      $("backup-list").replaceChildren(...data.items.map(backup=>{
        const card=element("article","backup-card"),top=element("div","backup-top"),name=element("div");
        name.append(element("h3","",formatDate(backup.created_at,true)),element("p","backup-filename",backup.id));
        const download=button("Baixar ZIP ↧","secondary-button",()=>downloadBackup(backup.id,download));download.disabled=!backup.downloadable;
        top.append(name,download);card.append(top);
        const metrics=element("div","backup-metrics");
        for(const [label,value] of [["Artigos",backup.articles===null ? "—" : number.format(backup.articles)],["Feeds observados",backup.feeds===null ? "—" : number.format(backup.feeds)],["Tamanho do banco",fileSize(backup.size_bytes)]]) {const item=element("div");item.append(element("small","",label),element("strong","",value));metrics.append(item);}
        card.append(metrics);if(backup.error) card.append(element("p","feed-form-error",backup.error));return card;
      }));
      if(!data.items.length) message("backups-message","Nenhum backup disponível","Gere sua primeira cópia pelo botão acima. Os backups automáticos também aparecerão aqui.");
    } catch(error) {
      if(error.name==="AbortError") return;
      $("backup-list").replaceChildren();$("backups-summary").textContent="Lista indisponível";
      message("backups-message","Não foi possível carregar os backups","Verifique a conexão e tente novamente.",loadBackups);
    } finally {if(controller===backupController) $("backup-list").setAttribute("aria-busy","false");}
  }
  async function loadBackupStatus(refreshList=true) {
    clearTimeout(backupTimer);
    try {
      const data=await request("/backups/status");
      const finished=backupRunning && data.status!=="running";
      backupRunning=data.status==="running";
      $("create-backup").disabled=backupRunning || backupRequest;
      $("create-backup").textContent=backupRunning ? "Gerando backup…" : "+ Gerar backup agora";
      $("backup-status").classList.toggle("backup-error",data.status==="failed");
      $("backup-status").textContent=backupRunning ? "Criando e verificando uma cópia. Você pode continuar usando a aplicação." : (data.status==="failed" ? data.error : (data.status==="completed" ? "Backup concluído. Baixe uma cópia para guardar fora do computador." : "Pronto para gerar um backup manual."));
      if(state.view==="backups" && (finished || (refreshList && !backupRunning))) await loadBackups();
    } catch(error) {
      $("create-backup").disabled=true;$("backup-status").textContent="Não foi possível consultar o backup. Tentando novamente…";
    }
    if(state.view==="backups") backupTimer=setTimeout(loadBackupStatus,backupRunning ? 3000 : 15000);
  }
  async function createBackup() {
    if(backupRequest || backupRunning) return;
    backupRequest=true;$("create-backup").disabled=true;$("backups-notice").hidden=true;
    try {
      const response=await fetch("/backups",{method:"POST",headers:{"X-Cyber-RSS-Request":"1"}});
      if(response.status!==409 && !response.ok) throw new Error(`HTTP ${response.status}`);
      if(response.ok) backupRunning=true;
    } catch(error) {
      $("backups-notice").textContent="Não foi possível confirmar o pedido de backup. Confira o estado antes de tentar novamente.";$("backups-notice").hidden=false;
    } finally {backupRequest=false;await loadBackupStatus();}
  }
  async function downloadBackup(id,control) {
    control.disabled=true;control.textContent="Preparando ZIP…";$("backups-notice").hidden=true;
    try {
      const response=await fetch("/backups/"+encodeURIComponent(id)+"/download");
      if(!response.ok) {
        const data=await response.json();throw new Error(typeof data.detail==="string" ? data.detail : "Não foi possível baixar esta cópia.");
      }
      const url=URL.createObjectURL(await response.blob()),link=element("a");
      link.href=url;link.download=id.replace(/\.sqlite3$/,".zip");document.body.append(link);link.click();link.remove();setTimeout(()=>URL.revokeObjectURL(url),30000);
    } catch(error) {
      $("backups-notice").textContent=error.message==="Failed to fetch" ? "Não foi possível baixar o backup. Verifique a conexão e tente novamente." : error.message;$("backups-notice").hidden=false;
    } finally {control.disabled=false;control.textContent="Baixar ZIP ↧";}
  }
  function detailSection(title,values,kind="") {
    const section=element("section","detail-section");section.append(element("h3","",title));
    if(!values.length) {section.append(element("p","detail-empty","Nenhum registro neste artigo."));return section;}
    const chips=element("div","detail-chips");values.forEach(value=>chips.append(element("span","pill"+(kind ? " entity-pill" : ""),value)));section.append(chips);return section;
  }
  function safeArticleURL(value) {try {const url=new URL(value);return ["https:","http:"].includes(url.protocol) ? url.href : null;}catch{return null;}}
  function renderDetail(article) {
    const content=$("detail-content"); const title=element("h2","",article.title);title.id="detail-title";
    content.replaceChildren(element("span","pill category-pill",categoryName(article.category || "Sem categoria")),title,element("p","detail-meta",`${article.source} · ${formatDate(article.published,true)}${article.author ? " · " + article.author : ""}`),element("p","detail-summary",article.summary || "Resumo não disponível neste feed."));
    content.append(detailSection("Tags",article.tags),detailSection("Malware detectado",article.malware,"entity"),detailSection("Atores detectados",article.threat_actors,"entity"));
    const iocs=element("section","detail-section");iocs.append(element("h3","","Indicadores de compromisso"));
    if(!article.iocs.length) iocs.append(element("p","detail-empty","Nenhum IOC extraído deste artigo."));
    else {const list=element("div","ioc-list");article.iocs.forEach(ioc=>{const row=element("div","ioc-row");const copy=button("Copiar","ioc-copy",async()=>{try{await navigator.clipboard.writeText(ioc.value);copy.textContent="Copiado";}catch{copy.textContent="Selecione o texto";}});copy.setAttribute("aria-label",`Copiar ${ioc.type}: ${ioc.value}`);row.append(element("span","ioc-type",ioc.type),element("code","ioc-value",ioc.value),copy);list.append(row);});iocs.append(list);}
    content.append(iocs,element("p","detail-notice","Os indicadores e nomes são extraídos do texto do feed. Valide o contexto antes de usá-los em uma investigação."));
    const actions=element("div","detail-actions"),url=safeArticleURL(article.url);
    if(url) {const link=element("a","primary-button","Abrir artigo original ↗");link.href=url;link.target="_blank";link.rel="noopener noreferrer";actions.append(link);}
    else actions.append(element("small","","Link original indisponível."));
    actions.append(element("small","","O resumo é o conteúdo disponibilizado pelo feed."));content.append(actions);
  }
  async function openDetail(id,changeURL=true) {
    detailController?.abort();const controller=detailController=new AbortController();
    state.article=id;if(changeURL) writeURL();
    const loadingTitle=element("h2","","Carregando artigo…");loadingTitle.id="detail-title";$("detail-content").replaceChildren(loadingTitle);
    if(!$("article-dialog").open) $("article-dialog").showModal();
    try {const article=await request("/articles/detail?"+new URLSearchParams({id}),controller.signal);if(controller===detailController) renderDetail(article);}
    catch(error) {if(error.name!=="AbortError") {const title=element("h2","","Artigo indisponível");title.id="detail-title";$("detail-content").replaceChildren(title,element("p","detail-empty","Não foi possível abrir este artigo. Ele pode não existir no arquivo ou a conexão está indisponível."),button("Tentar novamente","secondary-button",()=>openDetail(id,false)));}}
  }
  function closeDetail(changeURL=true) {detailController?.abort();if($("article-dialog").open) $("article-dialog").close();if(changeURL) {state.article="";writeURL(true);}}
  async function loadCollection() {
    clearTimeout(collectionTimer);
    try {
      const data=await request("/collection");
      const running=data.status==="running", finished=collectionWasRunning && !running;
      collectionWasRunning=running;syncFeedActions();
      $("collect-now").disabled=running || collectionRequest;
      $("force-refresh").disabled=running || collectionRequest;
      $("collect-now").textContent=running ? "Coleta em andamento…" : "↻ Coletar agora";
      $("collection-status").classList.toggle("collection-error",data.status==="failed");
      if(running) $("collection-status").textContent=data.source==="worker" ? "O coletor automático está trabalhando. Aguarde para iniciar outra coleta." : "Baixando e processando os feeds. Você pode continuar consultando os artigos.";
      else if(data.status==="failed") $("collection-status").textContent=data.error;
      else if(data.result?.cache_used) $("collection-status").textContent="O arquivo ainda está atualizado. Para baixar os feeds novamente, marque a opção de ignorar o intervalo.";
      else if(data.result) $("collection-status").textContent=`Coleta concluída: ${number.format(data.result.feeds_downloaded)} feeds baixados, ${number.format(data.result.feeds_failed)} com erro e ${number.format(data.result.articles_saved)} artigos salvos ou atualizados.`;
      else $("collection-status").textContent="Busque novos artigos sem esperar a próxima coleta automática.";
      if(running || finished) await Promise.allSettled([loadSummary(), ...(state.view==="feeds" ? [loadFeeds()] : [])]);
      if(finished) await Promise.allSettled([loadFacets(),loadView()]);
      // Also detect automatic collections that start while this page is open.
      collectionTimer=setTimeout(loadCollection,running ? 3000 : 15000);
    } catch(error) {
      $("collect-now").disabled=true;
      $("collection-status").textContent="Não foi possível consultar a coleta. Tentando novamente…";
      collectionTimer=setTimeout(loadCollection,5000);
    }
  }
  async function collectNow() {
    if(collectionRequest || collectionWasRunning) return;
    collectionRequest=true; $("collect-now").disabled=true; $("force-refresh").disabled=true;
    $("collection-status").textContent="Solicitando coleta…";
    try {
      const response=await fetch("/collection",{method:"POST",headers:{"Content-Type":"application/json","X-Cyber-RSS-Request":"1"},body:JSON.stringify({force_refresh:$("force-refresh").checked})});
      if(response.status!==409 && !response.ok) throw new Error(`HTTP ${response.status}`);
      if(response.ok) collectionWasRunning=true;
    } catch(error) {
      $("collection-status").textContent="Não foi possível confirmar o início da coleta. Verificando o estado…";
    } finally {
      collectionRequest=false;
      await loadCollection();
    }
  }
  async function refresh() {
    $("refresh").disabled=true; $("global-message").hidden=true;
    const results=await Promise.allSettled([loadFacets(),loadSummary(),loadCollection(),loadView()]);
    if(results[0].status==="rejected" || results[1].status==="rejected") {$("global-message").textContent="Não foi possível atualizar os filtros ou o resumo da coleta. Tente atualizar a tela novamente.";$("global-message").hidden=false;}
    $("refresh").disabled=false;
  }
  $("search-form").addEventListener("submit",event=>{event.preventDefault();updateArticles({q:$("search").value.trim(),source:$("source").value,tag:$("tag").value.trim()});});
  $("filters-form").addEventListener("submit",event=>{event.preventDefault();updateArticles({source:$("source").value,tag:$("tag").value.trim()});});
  $("source").addEventListener("change",()=>updateArticles({source:$("source").value}));
  $("tag").addEventListener("change",()=>updateArticles({tag:$("tag").value.trim()}));
  for(const [id,key] of [["result-limit","limit"],["result-order","order"],["result-period","period"],["search-match","match"],["fuzzy-threshold","fuzzy_threshold"]]) $(id).addEventListener("change",()=>{
    if(!$(id).checkValidity()) {$(id).reportValidity();return;}
    updateArticles({[key]:["limit","fuzzy_threshold"].includes(key) ? Number($(id).value) : $(id).value});
  });
  $("clear-filters").addEventListener("click",()=>updateArticles({q:"",category:"",source:"",tag:"",limit:20,order:"newest",period:"all",match:"fuzzy",fuzzy_threshold:80}));
  $("all-categories").addEventListener("click",()=>updateArticles({category:""}));
  $("nav-backups").addEventListener("click",()=>navigate("backups"));
  $("create-backup").addEventListener("click",createBackup);
  $("nav-sources").addEventListener("click",()=>navigate("sources"));
  $("sources-filter").addEventListener("change",renderSources);
  $("add-feed").addEventListener("click",()=>openFeed());
  $("close-feed").addEventListener("click",()=>$("feed-dialog").close());
  $("cancel-feed").addEventListener("click",()=>$("feed-dialog").close());
  $("feed-form").addEventListener("submit",event=>{event.preventDefault();saveFeed({...(editingFeed ? {id:editingFeed.id} : {}),name:$("feed-name").value.trim(),url:$("feed-url").value.trim(),category:$("feed-category").value.trim(),description:$("feed-description").value.trim() || null,enabled:$("feed-enabled").checked});});
  $("nav-topics").addEventListener("click",()=>navigate("topics"));
  $("topics-limit").addEventListener("change",()=>{state.topicLimit=Number($("topics-limit").value);writeURL();loadTopics();});
  $("nav-articles").addEventListener("click",()=>navigate("articles"));$("nav-feeds").addEventListener("click",()=>navigate("feeds"));$("stat-errors-button").addEventListener("click",()=>navigate("feeds","error"));
  $("collect-now").addEventListener("click",collectNow);
  $("refresh").addEventListener("click",refresh);
  $("previous").addEventListener("click",()=>{state.offset=Math.max(0,state.offset-state.limit);writeURL();loadArticles();$("results-title").scrollIntoView({block:"start",behavior:"smooth"});});
  $("next").addEventListener("click",()=>{state.offset+=state.limit;writeURL();loadArticles();$("results-title").scrollIntoView({block:"start",behavior:"smooth"});});
  $("feed-filter").addEventListener("change",()=>{state.feedStatus=$("feed-filter").value;state.feedOffset=0;writeURL();loadFeeds();});
  $("feeds-previous").addEventListener("click",()=>{state.feedOffset=Math.max(0,state.feedOffset-feedLimit);writeURL();loadFeeds();});
  $("feeds-next").addEventListener("click",()=>{state.feedOffset+=feedLimit;writeURL();loadFeeds();});
  $("close-detail").addEventListener("click",()=>closeDetail());$("article-dialog").addEventListener("cancel",event=>{event.preventDefault();closeDetail();});
  $("article-dialog").addEventListener("click",event=>{const box=$("article-dialog").getBoundingClientRect();if(event.target===$("article-dialog") && (event.clientX<box.left || event.clientX>box.right || event.clientY<box.top || event.clientY>box.bottom)) closeDetail();});
  $("menu-toggle").addEventListener("click",()=>{const open=$("sidebar").classList.toggle("open");$("menu-toggle").setAttribute("aria-expanded",String(open));syncMenuAccessibility();});
  document.addEventListener("click",event=>{if($("sidebar").classList.contains("open") && !$("sidebar").contains(event.target) && !$("menu-toggle").contains(event.target)) closeMenu();});
  document.addEventListener("keydown",event=>{if(event.key==="Escape") closeMenu();});
  window.addEventListener("popstate",()=>{closeDetail(false);state=readURL();controls();loadView();if(state.article) openDetail(state.article,false);});
  mobileNavigation.addEventListener("change",syncMenuAccessibility);syncMenuAccessibility();
  controls();refresh();if(state.article) openDetail(state.article,false);
})();
