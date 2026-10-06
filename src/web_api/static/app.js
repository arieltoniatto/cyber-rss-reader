(() => {
  "use strict";
  const $ = (id) => document.getElementById(id);
  const limit = 20;
  const labels = {apt:"APT", detection:"Detecção", dfir:"DFIR", exploit:"Exploits", government:"Governo", malware:"Malware", news:"Notícias", osint:"OSINT", podcasts:"Podcasts", threat_hunting:"Threat hunting", threat_intelligence:"Threat intelligence", vendors:"Fornecedores", vulnerability:"Vulnerabilidades"};
  const number = new Intl.NumberFormat("pt-BR");
  const dates = new Intl.DateTimeFormat("pt-BR", {day:"2-digit", month:"short", year:"numeric"});
  const timestamps = new Intl.DateTimeFormat("pt-BR", {dateStyle:"short", timeStyle:"short"});
  let state = readURL(), articleController, detailController, feedController;
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
    return {q, category:(params.get("category") || "").slice(0,200), source:(params.get("source") || "").slice(0,200), tag:(params.get("tag") || "").slice(0,200), offset:Math.min(q ? 10000 : 1000000, offset), view:params.get("view") === "feeds" ? "feeds" : "articles", feedStatus:["success","error","collecting"].includes(params.get("status")) ? params.get("status") : "", feedOffset:Math.min(1000000, Math.max(0, Math.floor(Number(params.get("feedOffset")) || 0))), article:params.get("article") || ""};
  }
  function writeURL(replace=false) {
    const params = new URLSearchParams();
    for (const key of ["q","category","source","tag","offset","article"]) if (state[key]) params.set(key,state[key]);
    if (state.view === "feeds") {params.set("view","feeds"); if(state.feedStatus) params.set("status",state.feedStatus); if(state.feedOffset) params.set("feedOffset",state.feedOffset);}
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
    $("feed-filter").value=state.feedStatus;
    $("articles-section").hidden=state.view!=="articles";
    $("feeds-section").hidden=state.view!=="feeds";
    $("nav-articles").classList.toggle("active",state.view==="articles");
    $("nav-feeds").classList.toggle("active",state.view==="feeds");
    $("nav-articles").setAttribute("aria-current",state.view==="articles" ? "page" : "false");
    $("nav-feeds").setAttribute("aria-current",state.view==="feeds" ? "page" : "false");
    $("breadcrumb-section").textContent=state.view==="feeds" ? "Coleta de feeds" : "Artigos";
    $("page-title").replaceChildren(document.createTextNode(state.view==="feeds" ? "Fontes sob observação" : "Seu radar de ameaças"),element("span","","."));
    $("page-description").textContent=state.view==="feeds" ? "Acompanhe tentativas, sucessos e erros de cada fonte." : "Notícias, pesquisas e indicadores em um só lugar.";
    $("results-title").textContent=state.q ? `Resultados para “${state.q}”` : (state.category ? categoryName(state.category) : "Últimos artigos");
    $("active-category").hidden=!state.category;
    $("active-category").textContent=categoryName(state.category);
    categoryNavigation();
  }
  const mobileNavigation = window.matchMedia("(max-width:800px)");
  function syncMenuAccessibility() {$("sidebar").inert=mobileNavigation.matches && !$("sidebar").classList.contains("open");}
  function closeMenu() {$("sidebar").classList.remove("open"); $("menu-toggle").setAttribute("aria-expanded","false");syncMenuAccessibility();}
  function updateArticles(changes) {
    state={...state,...changes,offset:0,view:"articles",article:""}; closeMenu(); closeDetail(false); writeURL(); controls(); loadArticles();
  }
  function navigate(view, feedStatus="") {
    state.view=view; state.feedStatus=feedStatus; state.feedOffset=0; state.article="";
    closeMenu(); closeDetail(false); writeURL(); controls();
    if(view==="feeds") loadFeeds(); else loadArticles();
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
    const params=new URLSearchParams({limit,offset:state.offset});
    for(const key of ["q","category","source","tag"]) if(state[key]) params.set(key,state[key]);
    try {
      const data=await request((state.q ? "/search?" : "/articles?")+params,controller.signal);
      if(controller!==articleController) return;
      $("article-list").replaceChildren(...data.items.map(renderArticle));
      $("results-note").textContent=`${data.items.length} ${data.items.length===1 ? "artigo" : "artigos"} nesta página`;
      $("page-number").textContent=`Página ${Math.floor(state.offset/limit)+1}`;
      $("previous").disabled=state.offset===0;
      $("next").disabled=!data.has_more || Boolean(state.q && state.offset+limit>10000);
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
    const params=new URLSearchParams({limit,offset:state.feedOffset});if(state.feedStatus) params.set("status",state.feedStatus);
    try {
      const data=await request("/feeds?"+params,controller.signal); if(controller!==feedController) return;
      renderStats(data); $("feed-list").replaceChildren(...data.items.map(renderFeed));
      $("feeds-page").textContent=`Página ${Math.floor(state.feedOffset/limit)+1}`;
      $("feeds-next").disabled=!data.has_more;$("feeds-previous").disabled=!state.feedOffset;
      if(!data.items.length) message("feeds-message","Nenhum feed neste estado",data.summary.total ? "Selecione outro estado para ver as fontes." : "Os estados aparecerão após a primeira coleta.");
    } catch(error) {if(error.name!=="AbortError") {$("feed-list").replaceChildren();message("feeds-message","Não foi possível carregar os feeds","Tente novamente para consultar o estado das fontes.",loadFeeds);}}
    finally {if(controller===feedController) $("feed-list").classList.remove("loading");}
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
  async function refresh() {
    $("refresh").disabled=true; $("global-message").hidden=true;
    const results=await Promise.allSettled([loadFacets(),loadSummary(),state.view==="feeds" ? loadFeeds() : loadArticles()]);
    if(results[0].status==="rejected" || results[1].status==="rejected") {$("global-message").textContent="Não foi possível atualizar os filtros ou o resumo da coleta. Tente atualizar a tela novamente.";$("global-message").hidden=false;}
    $("refresh").disabled=false;
  }
  $("search-form").addEventListener("submit",event=>{event.preventDefault();updateArticles({q:$("search").value.trim(),source:$("source").value,tag:$("tag").value.trim()});});
  $("filters-form").addEventListener("submit",event=>{event.preventDefault();updateArticles({source:$("source").value,tag:$("tag").value.trim()});});
  $("source").addEventListener("change",()=>updateArticles({source:$("source").value}));
  $("tag").addEventListener("change",()=>updateArticles({tag:$("tag").value.trim()}));
  $("clear-filters").addEventListener("click",()=>updateArticles({q:"",category:"",source:"",tag:""}));
  $("all-categories").addEventListener("click",()=>updateArticles({category:""}));
  $("nav-articles").addEventListener("click",()=>navigate("articles"));$("nav-feeds").addEventListener("click",()=>navigate("feeds"));$("stat-errors-button").addEventListener("click",()=>navigate("feeds","error"));
  $("refresh").addEventListener("click",refresh);
  $("previous").addEventListener("click",()=>{state.offset=Math.max(0,state.offset-limit);writeURL();loadArticles();$("results-title").scrollIntoView({block:"start",behavior:"smooth"});});
  $("next").addEventListener("click",()=>{state.offset+=limit;writeURL();loadArticles();$("results-title").scrollIntoView({block:"start",behavior:"smooth"});});
  $("feed-filter").addEventListener("change",()=>{state.feedStatus=$("feed-filter").value;state.feedOffset=0;writeURL();loadFeeds();});
  $("feeds-previous").addEventListener("click",()=>{state.feedOffset=Math.max(0,state.feedOffset-limit);writeURL();loadFeeds();});
  $("feeds-next").addEventListener("click",()=>{state.feedOffset+=limit;writeURL();loadFeeds();});
  $("close-detail").addEventListener("click",()=>closeDetail());$("article-dialog").addEventListener("cancel",event=>{event.preventDefault();closeDetail();});
  $("article-dialog").addEventListener("click",event=>{const box=$("article-dialog").getBoundingClientRect();if(event.target===$("article-dialog") && (event.clientX<box.left || event.clientX>box.right || event.clientY<box.top || event.clientY>box.bottom)) closeDetail();});
  $("menu-toggle").addEventListener("click",()=>{const open=$("sidebar").classList.toggle("open");$("menu-toggle").setAttribute("aria-expanded",String(open));syncMenuAccessibility();});
  document.addEventListener("click",event=>{if($("sidebar").classList.contains("open") && !$("sidebar").contains(event.target) && !$("menu-toggle").contains(event.target)) closeMenu();});
  document.addEventListener("keydown",event=>{if(event.key==="Escape") closeMenu();});
  window.addEventListener("popstate",()=>{closeDetail(false);state=readURL();controls();if(state.view==="feeds") loadFeeds();else loadArticles();if(state.article) openDetail(state.article,false);});
  mobileNavigation.addEventListener("change",syncMenuAccessibility);syncMenuAccessibility();
  controls();refresh();if(state.article) openDetail(state.article,false);
})();
