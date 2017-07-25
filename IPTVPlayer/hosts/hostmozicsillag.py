# -*- coding: utf-8 -*-
###################################################
# LOCAL import
###################################################
from Plugins.Extensions.IPTVPlayer.components.iptvplayerinit import TranslateTXT as _, SetIPTVPlayerLastHostError
from Plugins.Extensions.IPTVPlayer.components.ihost import CHostBase, CBaseHostClass, CDisplayListItem, RetHost, CUrlItem, ArticleContent
from Plugins.Extensions.IPTVPlayer.tools.iptvtools import printDBG, printExc, CSearchHistoryHelper, remove_html_markup, GetLogoDir, GetCookieDir, byteify, rm
from Plugins.Extensions.IPTVPlayer.libs.pCommon import common, CParsingHelper
import Plugins.Extensions.IPTVPlayer.libs.urlparser as urlparser
from Plugins.Extensions.IPTVPlayer.libs.youtube_dl.utils import clean_html
from Plugins.Extensions.IPTVPlayer.tools.iptvtypes import strwithmeta
###################################################

###################################################
# FOREIGN import
###################################################
import urlparse
import time
import re
import urllib
import string
import random
import base64
from copy import deepcopy
from hashlib import md5
try:    import json
except Exception: import simplejson as json
from Components.config import config, ConfigSelection, ConfigYesNo, ConfigText, getConfigListEntry
###################################################


###################################################
# E2 GUI COMMPONENTS 
###################################################
from Plugins.Extensions.IPTVPlayer.components.asynccall import MainSessionWrapper
from Screens.MessageBox import MessageBox
###################################################

###################################################
# Config options for HOST
###################################################

def GetConfigList():
    optionList = []
    return optionList
###################################################

def gettytul():
    return 'http://mozicsillag.cc/'

class MuziCsillangCC(CBaseHostClass):
 
    def __init__(self):
        CBaseHostClass.__init__(self, {'history':'mozicsillag.cc', 'cookie':'mozicsillag.cc.cookie', 'cookie_type':'MozillaCookieJar'})
        self.DEFAULT_ICON_URL = 'http://mozicsillag.cc/img/logo.png'
        self.USER_AGENT = 'User-Agent=Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko/20100101 Firefox/40.0'
        self.HEADER = {'User-Agent': self.USER_AGENT, 'DNT':'1', 'Accept': 'text/html'}
        self.AJAX_HEADER = dict(self.HEADER)
        self.AJAX_HEADER.update( {'X-Requested-With': 'XMLHttpRequest'} )
        self.MAIN_URL = 'http://mozicsillag.cc/'
        self.cacheLinks    = {}
        self.cacheFilters  = {}
        self.cacheFiltersKeys = []
        self.cacheSortOrder = []
        self.defaultParams = {'header':self.HEADER, 'use_cookie': True, 'load_cookie': True, 'save_cookie': True, 'cookiefile': self.COOKIE_FILE}
    
        self.MAIN_CAT_TAB = [#{'category':'list_filters',    'title': _('Catalog'),            'url':self.getFullUrl('kereses.php')   },
                             {'category':'list_movies',     'title': _('Movies'),             'url':self.getMainUrl()  },
                             {'category':'list_series',     'title': _('Series'),             'url':self.getMainUrl()  },
                             
                             {'category':'search',            'title': _('Search'), 'search_item':True,},
                             {'category':'search_history',    'title': _('Search history'),            } 
                            ]
                            
    def getFullIconUrl(self, url):
        url = url.replace('&amp;', '&')
        return CBaseHostClass.getFullIconUrl(self, url)
        
    def getPage(self, baseUrl, addParams = {}, post_data = None):
        if addParams == {}:
            addParams = dict(self.defaultParams)
        
        def _getFullUrl(url):
            if self.cm.isValidUrl(url):
                return url
            else:
                return urlparse.urljoin(baseUrl, url)
            
        addParams['cloudflare_params'] = {'domain':self.up.getDomain(baseUrl), 'cookie_file':self.COOKIE_FILE, 'User-Agent':self.USER_AGENT, 'full_url_handle':_getFullUrl}
        sts, data = self.cm.getPageCFProtection(baseUrl, addParams, post_data)
        return sts, data
    
    def fillCacheFilters(self, cItem):
        printDBG("MuziCsillangCC.listCategories")
        self.cacheFilters = {}
        self.cacheFiltersKeys = []
        
        sts, data = self.getPage(cItem['url'])
        if not sts: return
        
        def addFilter(data, marker, baseKey, addAll=True, titleBase=''):
            key = 'f_' + baseKey
            self.cacheFilters[key] = []
            for item in data:
                value = self.cm.ph.getSearchGroups(item, marker + '''="([^"]+?)"''')[0]
                if value == '': continue
                title = self.cleanHtmlStr(item)
                if title in ['Összes']:
                    addAll = False
                self.cacheFilters[key].append({'title':title.title(), key:value})
                
            if len(self.cacheFilters[key]):
                if addAll: self.cacheFilters[key].insert(0, {'title':_('All')})
                self.cacheFiltersKeys.append(key)
        
        data = self.cm.ph.getAllItemsBeetwenMarkers(data, '<div class="row form-group">', '</select>')
        for tmp in data:
            key = self.cm.ph.getSearchGroups(tmp, '''name="([^"]+?)"''')[0]
            tmp = self.cm.ph.getAllItemsBeetwenMarkers(tmp, '<option', '</option>')
            addFilter(tmp, 'value', key, False)
        
        printDBG(self.cacheFilters)
        
    def listFilters(self, cItem, nextCategory):
        printDBG("MuziCsillangCC.listFilters")
        cItem = dict(cItem)
        
        f_idx = cItem.get('f_idx', 0)
        if f_idx == 0: self.fillCacheFilters(cItem)
        
        if 0 == len(self.cacheFiltersKeys): return
        
        filter = self.cacheFiltersKeys[f_idx]
        f_idx += 1
        cItem['f_idx'] = f_idx
        if f_idx  == len(self.cacheFiltersKeys):
            cItem['category'] = nextCategory
        self.listsTab(self.cacheFilters.get(filter, []), cItem)
        
    def listItems(self, cItem, nextCategory):
        printDBG("MuziCsillangCC.listItems")
        url = cItem['url']
        page = cItem.get('page', 1)
        sort = cItem.get('f_sort', '')
        
        query = {}
        for key in self.cacheFiltersKeys:
            baseKey = key[2:] # "f_"
            if key in cItem: query[baseKey] = urllib.quote(cItem[key])
        
        query = urllib.urlencode(query)
        if not url.endswith('/'): url += '/'
        if sort != '': url += sort + '/'
        if query != '': url += base64.b64encode(query)
        if page > 1: url += '?page=%s' % page
        
        sts, data = self.getPage(url)
        if not sts: return
        
        nextPage = self.cm.ph.getDataBeetwenMarkers(data, 'pagination', '</ul>')[1]
        if  '' != self.cm.ph.getSearchGroups(nextPage, 'page=(%s)[^0-9]' % (page+1))[0]: nextPage = True
        else: nextPage = False
        
        data = self.cm.ph.getDataBeetwenMarkers(data, '<ul class="small-block-grid', '</ul>')[1]        
        data = self.cm.ph.getAllItemsBeetwenMarkers(data, '<li', '</li>')
        reFlagObj = re.compile('''<img[^>]+?src=['"][^"^']+?/([^/]+?)\.png['"]''')
        for item in data:
            url = self.getFullUrl( self.cm.ph.getSearchGroups(item, '''href=['"]([^"^']+?)['"]''')[0] )
            if not self.cm.isValidUrl(url): continue
            
            icon = self.getFullIconUrl( self.cm.ph.getSearchGroups(item, '''data-original=['"]([^"^']+?\.jpe?g)['"]''')[0] )
            title = self.cleanHtmlStr( self.cm.ph.getDataBeetwenMarkers(item, '<strong', '</strong>')[1] )
            if title == '': title = self.cleanHtmlStr( self.cm.ph.getDataBeetwenMarkers(item, '<h2', '</h2>')[1] )
            
            # desc start
            descTab = []
            tmp = self.cm.ph.getDataBeetwenMarkers(item, '</strong>', '</div>')[1]
            flags = reFlagObj.findall(tmp)
            if len(flags): descTab.append(' | '.join(flags))
            tmp = tmp.split('<br>')
            for t in tmp:
                t = self.cleanHtmlStr(t)
                if t == '': continue
                descTab.append(t)
            ######
            
            params = dict(cItem)
            params = {'good_for_fav': True, 'title':title, 'url':url, 'desc':'[/br]'.join(descTab), 'icon':icon}
            params['category'] = nextCategory
            self.addDir(params)
        
        if nextPage and len(self.currList) > 0:
            params = dict(cItem)
            params.update({'title':_("Next page"), 'page':page+1})
            self.addDir(params)
            
    def _listCategories(self, cItem, nextCategory, m1, m2):
        printDBG("MuziCsillangCC._listCategories")
        sts, data = self.getPage(cItem['url'])
        if not sts: return
        
        data = self.cm.ph.getDataBeetwenMarkers(data, m1, m2)[1]
        data = self.cm.ph.getAllItemsBeetwenMarkers(data, '<a', '</a>')
        for item in data:
            url   = self.getFullUrl(self.cm.ph.getSearchGroups(item, '''href=['"]([^'^"]+?)['"]''')[0])
            title = self.cleanHtmlStr(item)
            params = dict(cItem)
            params.update({'category':nextCategory, 'title':title, 'url':url})
            self.addDir(params)
        
    def listMovies(self, cItem, nextCategory):
        printDBG("MuziCsillangCC.listMovies")
        self._listCategories(cItem, nextCategory, 'Filmek</a>', 'has-dropdown not-click')
        
    def listSeries(self, cItem, nextCategory):
        printDBG("MuziCsillangCC.listSeries")
        self._listCategories(cItem, nextCategory, 'Sorozatok</a>', '/sztarok"')
        
    def listSort(self, cItem, nextCategory):
        printDBG("MuziCsillangCC.listSeries")
        if 0 == len(self.cacheSortOrder):
            sts, data = self.getPage(self.getFullUrl('/filmek-online')) # sort order is same for movies and series
            if not sts: return
            data = self.cm.ph.getDataBeetwenMarkers(data, '<dl ', '</dl>')[1]
            data = self.cm.ph.getAllItemsBeetwenMarkers(data, '<a', '</a>')
            for item in data:
                sort  = self.cm.ph.getSearchGroups(item, '''href=['"]([^'^"]+?)['"]''')[0].split('/')[-1]
                if sort == '': continue
                title = self.cleanHtmlStr(item)
                self.cacheSortOrder.append({'title':title, 'f_sort':sort})
        
        for item in self.cacheSortOrder:
            params = dict(cItem)
            params.update({'category':nextCategory})
            params.update(item)
            self.addDir(params)
        
    def exploreItem(self, cItem):
        printDBG("MuziCsillangCC.exploreItem")
        
        sts, data = self.getPage(cItem['url'])
        if not sts: return
        
        desc = self.cleanHtmlStr(self.cm.ph.getDataBeetwenMarkers(data, '<p>', '</p>')[1])
        
        # trailer 
        tmp = self.cm.ph.rgetAllItemsBeetwenMarkers(data, '</iframe>', '<h2')
        for idx in xrange(len(tmp)):
            url = self.getFullUrl(self.cm.ph.getSearchGroups(tmp[idx], '''src=['"]([^'^"]+?)['"]''')[0])
            if url.endswith('/thanks'): continue
            title = self.cleanHtmlStr(tmp[idx])
            if title.endswith(':'): title = title[:-1]
            if title == '': title = '%s - %s' %(cItem['title'], _('trailer'))
            if 1 == self.up.checkHostSupport(url):
                params = dict(cItem)
                params.update({'good_for_fav': False, 'title':'%s. %s' % (idx+1, title), 'prev_title':cItem['title'], 'url':url, 'prev_url':cItem['url'], 'prev_desc':cItem.get('desc', ''), 'desc':desc})
                self.addVideo(params)
        
        sourcesLink = self.cm.ph.rgetDataBeetwenMarkers2(data, 'Beküldött linkek megtekintése', '<a', caseSensitive=False)[1]
        sourcesLink = self.cm.ph.getSearchGroups(sourcesLink, '''href=['"](https?://[^'^"]+?)['"]''')[0]
        if not self.cm.isValidUrl(sourcesLink):
            printDBG("MuziCsillangCC.exploreItem - missing link for sources")
            return
        
        sts, data = self.getPage(sourcesLink)
        if not sts: return []
        
        self.cacheLinks  = {}
        
        data = self.cm.ph.getDataBeetwenMarkers(data, '<div class="links_holder', '<script type="text/javascript">', False)[1]
        data = data.split('accordion-episodes')
        episodesTab = []
        for tmp in data:
            episodeName = self.cleanHtmlStr(self.cm.ph.getSearchGroups(tmp, '''<div[^>]+?textHolder[^>]*?>([^<]+?)<''')[0])
            
            tmp = tmp.split('panel')
            for item in tmp:
                url = self.cm.ph.getSearchGroups(item, '''<a[^>]+?href=['"]([^'^"]*?watch[^'^"]*?)['"]''')[0]
                
                if url != '': url = urlparse.urljoin(sourcesLink, url)
                if not self.cm.isValidUrl(url): continue
                serverName = []
                item = self.cm.ph.getAllItemsBeetwenMarkers(item, '<div', '</div>')
                for t in item:
                    if 'link_flag' in t:
                        t = self.cm.ph.getSearchGroups(t, '''<img[^>]+?src=['"][^"^']+?/([^/]+?)\.png['"]''')[0]
                    t = self.cleanHtmlStr(t)
                    if t != '': serverName.append(t)
                serverName = ' | '.join(serverName)
                
                if episodeName not in episodesTab:
                    episodesTab.append(episodeName)
                    self.cacheLinks[episodeName] = []
                self.cacheLinks[episodeName].append({'name':serverName, 'url':url, 'need_resolve':1})
        
        for item in episodesTab:
            params = dict(cItem)
            title = cItem['title']
            if item != '': title += ' : ' + item
            params.update({'good_for_fav': False, 'title':title, 'links_key':item, 'prev_desc':cItem.get('desc', ''), 'desc':desc})
            self.addVideo(params)

    def listSearchResult(self, cItem, searchPattern, searchType):
        printDBG("MuziCsillangCC.listSearchResult cItem[%s], searchPattern[%s] searchType[%s]" % (cItem, searchPattern, searchType))
        cItem = dict(cItem)
        query = base64.b64encode('search_term=%s&search_type=0&search_where=0&search_rating_start=1&search_rating_end=10&search_year_from=1900&search_year_to=2100' % urllib.quote_plus(searchPattern) ) 
        cItem['url'] = self.getFullUrl('kereses/' + query)
        self.listItems(cItem, 'explore_item')
        
    def getLinksForVideo(self, cItem):
        printDBG("MuziCsillangCC.getLinksForVideo [%s]" % cItem)
        retTab = []
        if 1 == self.up.checkHostSupport(cItem.get('url', '')):
            videoUrl = cItem['url'].replace('youtu.be/', 'youtube.com/watch?v=')
            return self.up.getVideoLinkExt(videoUrl)
        key = cItem.get('links_key', '')
        return self.cacheLinks.get(key, [])
        
    def getVideoLinks(self, videoUrl):
        printDBG("MuziCsillangCC.getVideoLinks [%s]" % videoUrl)
        videoUrl = strwithmeta(videoUrl)
        urlTab = []
        
        # mark requested link as used one
        if len(self.cacheLinks.keys()):
            for key in self.cacheLinks:
                for idx in range(len(self.cacheLinks[key])):
                    if videoUrl in self.cacheLinks[key][idx]['url']:
                        if not self.cacheLinks[key][idx]['name'].startswith('*'):
                            self.cacheLinks[key][idx]['name'] = '*' + self.cacheLinks[key][idx]['name']
                        break
                        
        try:
            httpParams = dict(self.defaultParams)
            httpParams['return_data'] = False
            
            sts, response = self.cm.getPage(videoUrl, httpParams)
            videoUrl = response.geturl()
            response.close()
        except Exception:
            printExc()
            return []
        
        if self.up.getDomain(self.getMainUrl()) in videoUrl:
            sts, data = self.getPage(videoUrl)
            if not sts: return []
            
            printDBG(data)
            tmp = re.compile('''<iframe[^>]+?src=['"]([^"^']+?)['"]''', re.IGNORECASE).findall(data)
            for url in tmp:
                if 1 == self.up.checkHostSupport(url):
                    videoUrl = url
                    break
        
        if self.cm.isValidUrl(videoUrl):
            urlTab = self.up.getVideoLinkExt(videoUrl)
        
        return urlTab
    
    def getFavouriteData(self, cItem):
        printDBG('MuziCsillangCC.getFavouriteData')
        params = {'type':cItem['type'], 'category':cItem.get('category', ''), 'title':cItem['title'], 'url':cItem['url'], 'desc':cItem['desc'], 'icon':cItem['icon']}
        return json.dumps(params) 
        
    def getLinksForFavourite(self, fav_data):
        printDBG('MuziCsillangCC.getLinksForFavourite')
        if self.MAIN_URL == None:
            self.selectDomain()
        links = []
        try:
            cItem = byteify(json.loads(fav_data))
            links = self.getLinksForVideo(cItem)
        except Exception: printExc()
        return links
        
    def setInitListFromFavouriteItem(self, fav_data):
        printDBG('MuziCsillangCC.setInitListFromFavouriteItem')
        if self.MAIN_URL == None:
            self.selectDomain()
        try:
            params = byteify(json.loads(fav_data))
        except Exception: 
            params = {}
            printExc()
        self.addDir(params)
        return True
        
    def getArticleContent(self, cItem):
        printDBG("MuziCsillangCC.getArticleContent [%s]" % cItem)
        retTab = []
        
        otherInfo = {}
        
        url = cItem.get('prev_url', '')
        if url == '': url = cItem.get('url', '')
        
        sts, data = self.getPage(url)
        if not sts: return retTab
        
        data = self.cm.ph.getDataBeetwenMarkers(data, '<div class="row" id="content-tab">', '<div id="zone')[1]
        
        title = '' #self.cleanHtmlStr(self.cm.ph.getDataBeetwenMarkers(data, '<div class="f_t_b">', '</div>')[1])
        icon  = self.getFullIconUrl( self.cm.ph.getSearchGroups(data, '''<img[^>]+?src=['"]([^"^']+?\.jpe?g[^"^']*?)["']''')[0] )
        desc  = self.cleanHtmlStr(self.cm.ph.getDataBeetwenMarkers(data, '<p>', '</p>', False)[1])
        
        for item in [('Rendező(k):', 'directors'),
                     ('Színészek:',     'actors'),
                     ('Kategoria:',      'genre')]:
            tmpTab = []
            tmp = self.cm.ph.getDataBeetwenMarkers(data, item[0], '</li>', False)[1].split('<br>')
            for t in tmp:
                t = self.cleanHtmlStr(t).replace(' , ',  ', ')
                if t != '': tmpTab.append(t)
            if len(tmpTab): otherInfo[item[1]] = ', '.join(tmpTab)
        
        for item in [('Játékidő:',     'duration'),
                     ('IMDB Pont:', 'imdb_rating'),
                     ('Nézettség:',       'views')]:
            tmp = self.cleanHtmlStr(self.cm.ph.getDataBeetwenMarkers(data, item[0], '</li>', False)[1])
            if tmp != '': otherInfo[item[1]] = tmp
        
        if title == '': title = cItem['title']
        if desc == '':  desc = cItem.get('desc', '')
        if icon == '':  icon = cItem.get('icon', self.DEFAULT_ICON_URL)
        
        return [{'title':self.cleanHtmlStr( title ), 'text': self.cleanHtmlStr( desc ), 'images':[{'title':'', 'url':self.getFullUrl(icon)}], 'other_info':otherInfo}]
    
    def handleService(self, index, refresh = 0, searchPattern = '', searchType = ''):
        printDBG('handleService start')
        
        CBaseHostClass.handleService(self, index, refresh, searchPattern, searchType)

        name     = self.currItem.get("name", '')
        category = self.currItem.get("category", '')
        mode     = self.currItem.get("mode", '')
        
        printDBG( "handleService: |||||||||||||||||||||||||||||||||||| name[%s], category[%s] " % (name, category) )
        self.currList = []
        
    #MAIN MENU
        if name == None:
            self.cacheLinks = {}
            self.listsTab(self.MAIN_CAT_TAB, {'name':'category'})
        elif category == 'list_filters':
            self.listFilters(self.currItem, 'list_items')
        elif category == 'list_movies':
            self.listMovies(self.currItem, 'list_sort')
        elif category == 'list_series':
            self.listSeries(self.currItem, 'list_sort')
        elif category == 'list_sort':
            self.listSort(self.currItem, 'list_items')
        elif category == 'list_items':
            self.listItems(self.currItem, 'explore_item')
        elif category == 'explore_item':
            self.exploreItem(self.currItem)
    #SEARCH
        elif category in ["search", "search_next_page"]:
            cItem = dict(self.currItem)
            cItem.update({'search_item':False, 'name':'category'}) 
            self.listSearchResult(cItem, searchPattern, searchType)
    #HISTORIA SEARCH
        elif category == "search_history":
            self.listsHistory({'name':'history', 'category': 'search'}, 'desc', _("Type: "))
        else:
            printExc()
        
        CBaseHostClass.endHandleService(self, index, refresh)

class IPTVHost(CHostBase):

    def __init__(self):
        CHostBase.__init__(self, MuziCsillangCC(), True, [])
        
    def withArticleContent(self, cItem):
        if (cItem['type'] != 'video' and cItem['category'] != 'explore_item'):
            return False
        return True
    
    