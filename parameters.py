import logging
import argparse

from cryptography.hazmat.primitives.asymmetric import dh
from Cryptodome.Random import random

from gmpy2 import mpz, is_prime, powmod


log = logging.getLogger('parameters')


bit_length = 2048
p = mpz(22012449077949273827028270859107030932809865597904272815230972114310552714233681841717695001862720528265052063323019406139281672873791608721551487596031421218726732479070598345042470408282975650490598154065186605002680115265675835060067855184770457678903260424825134011190573783335506217951255995327720361576872277526857813940817168490821646275643315512040214128892336252159776942542967019825137485952655996042801458102266520033222705695349084041349439276304774852882795195502114709641922925180626468596348366209429490451999419038782365506661062534134363412374157638197526172013802199566896975632604663600802860685659)
q = mpz(11006224538974636913514135429553515466404932798952136407615486057155276357116840920858847500931360264132526031661509703069640836436895804360775743798015710609363366239535299172521235204141487825245299077032593302501340057632837917530033927592385228839451630212412567005595286891667753108975627997663860180788436138763428906970408584245410823137821657756020107064446168126079888471271483509912568742976327998021400729051133260016611352847674542020674719638152387426441397597751057354820961462590313234298174183104714745225999709519391182753330531267067181706187078819098763086006901099783448487816302331800401430342829)
g = mpz(1448637677689651586530119062225693398855383037107542071721196706508432154311174661095686173374142948639814402332768564992262016080491671545344664618690054374153410950819075219225909403542103677771933805688006853988139993176667280557550418143338418554889278541233542447385947959308746138931080044716710161716884552680146052924219619778020055115896548801014510863273364055557912161503505821897913351203778307717044593421893533156361967069904108984098686883898456175048835279456622247627375449973387284987596770416840362535023408308210809065350383025589257715593975390185434172429267778451921373884510697024426518698108)
h = mpz(220780183700577819320568596015497387298747276165051236953898935064736780039543946580519751283219198511526569286723496903874514550814231169903329823753920657891411097674126835974894725072064578289790480666234034892511821615913653796375145271977167051668447666454109209775572390907530887564692185458336016903710465327267908062539285067408887918810912450100150002327949483383512605435225567462342849534319466585289042719604176328646097082672142308756211710038719663141826592149527935434624568177609567745457155154525958217636233575214363754494572266989893845256833098321695226412554164864708569494050053143868817979250)


def new_params(bits=bit_length):
    log.info('Finding safe prime')
    parameters = dh.generate_parameters(generator=2, key_size=bits)

    p = parameters.parameter_numbers().p
    q = (p - 1) >> 1
    assert is_prime(p)
    assert is_prime(q)
    assert p == (2 * q) + 1
    log.info('Finding generator')
    g = 2
    while powmod(g, q, p) != 1:
        g = random.randint(2, q - 2)
    assert powmod(g, q, p) == 1
    log.info('Finding Pedersen value')
    h = powmod(g, random.randint(2, q - 2), p)
    log.info('Done!')
    return mpz(p), mpz(q), mpz(g), mpz(h)


def verify_params(p, q, g):
    assert is_prime(p)
    assert is_prime(q)
    assert p == (2 * q) + 1
    assert powmod(g, q, p) == 1
    return True


if __name__ == '__main__':
    arg_parser = argparse.ArgumentParser()
    arg_parser.add_argument('--generate', '-G', action='store_true', help='Generate new parameters')
    args = arg_parser.parse_args()

    logging.basicConfig(level=logging.DEBUG)

    if args.generate:
        log.info('Generating new crytpo parameters.')
        p, q, g, h = new_params(bit_length)
        log.info(f'p = {p}')
        log.info(f'q = {q}')
        log.info(f'g = {g}')
        log.info(f'h = {h}')

    if verify_params(p, q, g):
        log.info('Crypto parameters are valid.')
    else:
        log.error('Invalid crypto parameters.')